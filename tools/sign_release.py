"""Protected post-build signing and independent verification; never builds or publishes.

Run in a separate offline SDK container, mounting private inputs read-only only
after the unsigned build has finished. No Gradle, project shell script or APK code
is executed here. Environment passwords remain supported without argv exposure;
an external password file is preferred.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from verify_release_apk import ROOT, TEST_SIGNER, sha256, verify
from apk_native_policy import zipalign_tool


# Only these literal tokens may reach failure output. Never interpolate an
# exception, SDK output, argv, environment value or private filesystem path.
STAGES = frozenset({'configuration', 'alignment', 'signing', 'verification', 'export', 'unknown'})
CATEGORIES = frozenset({
    'INVALID_ARGUMENTS', 'OUTPUT_NOT_NEW', 'INPUT_MISSING', 'INVALID_SIGNER_PIN',
    'INVALID_PRIVATE_INPUT', 'INVALID_PASSWORD_SOURCE', 'INVALID_PASSWORD_FORMAT',
    'TOOL_NOT_FOUND', 'ACCESS_DENIED', 'FILE_NOT_FOUND', 'IO_ERROR', 'SDK_NONZERO_EXIT',
    'SIGNATURE_CHECK_FAILED', 'ALIGNMENT_CHECK_FAILED', 'APK_READ_FAILED',
    'PACKAGE_VERSION_MISMATCH', 'MANIFEST_INVALID', 'SDK_LEVELS_MISMATCH',
    'SPLIT_REQUIREMENT', 'PROVIDER_AUTHORITIES_INVALID', 'SIGNATURE_INVALID',
    'CERTIFICATE_MISMATCH', 'TEST_CERTIFICATE_REJECTED', 'ZIP_INVALID', 'DEX_INVALID',
    'DEX_LIMIT_EXCEEDED', 'DIAGNOSTICS_PRESENT', 'NATIVE_INVALID', 'NOTICES_MISSING',
    'INPUT_VERIFICATION_FAILED', 'METADATA_INVALID', 'MISSING_APK_ENTRY',
    'EXPORT_HASH_MISMATCH', 'VALIDATION_FAILED', 'INTERNAL_ERROR',
})


class SigningFailure(ValueError):
    """Non-sensitive failure data; never retains the original error as its message."""
    def __init__(self, stage, category):
        self.stage = stage if type(stage) is str and stage in STAGES else 'unknown'
        self.category = category if type(category) is str and category in CATEGORIES else 'INTERNAL_ERROR'
        super().__init__('stage=' + self.stage + ' category=' + self.category)


def failure_message(error):
    # Revalidate even a mutated/forged failure object before rendering it.
    safe = SigningFailure(getattr(error, 'stage', None), getattr(error, 'category', None)) if type(error) is SigningFailure else SigningFailure('unknown', 'INTERNAL_ERROR')
    return ('Protected signing/verification failed; stage=' + safe.stage +
            ' category=' + safe.category + '; no candidate is approved.\n')


def failure_category(stage, error):
    """Classify known failures without printing or decoding subprocess output."""
    if isinstance(error, PermissionError):
        return 'ACCESS_DENIED'
    if isinstance(error, FileNotFoundError):
        return 'TOOL_NOT_FOUND' if stage in ('alignment', 'signing') else 'FILE_NOT_FOUND'
    if isinstance(error, subprocess.CalledProcessError):
        # Inspect only the allowlisted tool basename, never render its path/argv/output.
        cmd = error.cmd
        if stage == 'verification' and isinstance(cmd, (list, tuple)) and cmd and type(cmd[0]) is str:
            tool = cmd[0].replace('\\', '/').rsplit('/', 1)[-1].lower()
            return {'apksigner': 'SIGNATURE_CHECK_FAILED', 'apksigner.bat': 'SIGNATURE_CHECK_FAILED',
                    'zipalign': 'ALIGNMENT_CHECK_FAILED', 'zipalign.exe': 'ALIGNMENT_CHECK_FAILED',
                    'aapt': 'APK_READ_FAILED', 'aapt.exe': 'APK_READ_FAILED'}.get(tool, 'SDK_NONZERO_EXIT')
        return 'SDK_NONZERO_EXIT'
    if isinstance(error, OSError):
        return 'IO_ERROR'
    if isinstance(error, zipfile.BadZipFile):
        return 'ZIP_INVALID'
    if isinstance(error, json.JSONDecodeError):
        return 'METADATA_INVALID'
    if isinstance(error, KeyError) and stage == 'verification':
        return 'MISSING_APK_ENTRY'
    # Compare only exact built-in ValueError string arguments. Do not call str(error),
    # evaluate arbitrary exception properties, or inspect raw SDK error output.
    if type(error) is ValueError and error.args and type(error.args[0]) is str:
        message = error.args[0]
        common = {
            'Signing output must be new and separate from inputs': 'OUTPUT_NOT_NEW',
            'Unsigned APK and approved Twitch input are required': 'INPUT_MISSING',
            'A pinned non-test EXPECTED_SIGNER_SHA256 is required': 'INVALID_SIGNER_PIN',
            'Supply exactly one of KSPASS_FILE (preferred) or KSPASS': 'INVALID_PASSWORD_SOURCE',
            'SDK alignment/signing failed; no verified artifact was exported': 'SDK_NONZERO_EXIT',
            'Export hash mismatch; do not use candidate': 'EXPORT_HASH_MISMATCH',
        }
        if message in common:
            return common[message]
        if stage == 'configuration':
            if message in ('KS must name an existing absolute external file',
                           'KS must be outside the Git repository and output directory',
                           'KSPASS_FILE must name an existing absolute external file',
                           'KSPASS_FILE must be outside the Git repository and output directory'):
                return 'INVALID_PRIVATE_INPUT'
            if message in ('Password file must contain one UTF-8 line without BOM',
                           'Password file must use UTF-8', 'Password file must contain one nonempty line',
                           'KSPASS must contain one nonempty line'):
                return 'INVALID_PASSWORD_FORMAT'
        if stage == 'verification':
            known = {
                'Missing package metadata': 'MANIFEST_INVALID',
                'Unexpected package/version': 'PACKAGE_VERSION_MISMATCH',
                'Unexpected SDK levels': 'SDK_LEVELS_MISMATCH',
                'Unexpected native extraction mode': 'NATIVE_INVALID',
                'APK still requires splits': 'SPLIT_REQUIREMENT', 'Split metadata remains': 'SPLIT_REQUIREMENT',
                'Expected nine unique provider authorities': 'PROVIDER_AUTHORITIES_INVALID',
                'APK v3 signature verification failed': 'SIGNATURE_INVALID',
                'Expected exactly one APK signer': 'SIGNATURE_INVALID',
                'Unexpected signing certificate': 'CERTIFICATE_MISMATCH',
                'Public bundled debug key is not a production signing identity': 'TEST_CERTIFICATE_REJECTED',
                'Duplicate entries or ZIP CRC failure': 'ZIP_INVALID',
                'Expected seven contiguous DEX files': 'DEX_INVALID',
                'Invalid DEX header': 'DEX_INVALID', 'DEX checksum failure': 'DEX_INVALID',
                'Conservative DEX pool limit exceeded': 'DEX_LIMIT_EXCEEDED',
                'Temporary notification diagnostics in production APK': 'DIAGNOSTICS_PRESENT',
                'BTTV injection missing from classes7.dex': 'DEX_INVALID',
                'Missing packaged license resource': 'NOTICES_MISSING',
                'Native architecture mismatch': 'NATIVE_INVALID',
                'Unexpected native ABI': 'NATIVE_INVALID',
                'Native ELF load alignment failure': 'NATIVE_INVALID',
                'Unexpected WebP decoder': 'NATIVE_INVALID',
                'Incomplete dual-ARM inventory': 'NATIVE_INVALID',
                'Original Twitch native library changed': 'NATIVE_INVALID',
            }
            if message in known:
                return known[message]
            if message.startswith(('Native compression/alignment failure: ', 'Invalid native ELF: ')):
                return 'NATIVE_INVALID'
            if message.startswith(('Duplicate bundle entries', 'Unexpected APK inventory;',
                                   'Secondary bundle must contain', 'Unvalidated Twitch APK variant: ', 'Invalid APK ZIP: ')):
                return 'INPUT_VERIFICATION_FAILED'
        return 'VALIDATION_FAILED'
    return 'INTERNAL_ERROR'


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error echoes unrecognized arguments (possibly secrets).
        self.exit(2, failure_message(SigningFailure('configuration', 'INVALID_ARGUMENTS')))


def external_file(value, name, output):
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(name + ' must name an existing absolute external file')
    path = path.resolve()
    if path == ROOT or ROOT in path.parents or path == output or output in path.parents:
        raise ValueError(name + ' must be outside the Git repository and output directory')
    return path


def signing_config(env, output):
    fingerprint = env.get('EXPECTED_SIGNER_SHA256', '')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', fingerprint) or fingerprint.upper() == TEST_SIGNER:
        raise ValueError('A pinned non-test EXPECTED_SIGNER_SHA256 is required')
    key = external_file(env.get('KS', ''), 'KS', output)
    password, password_file = env.get('KSPASS', ''), env.get('KSPASS_FILE', '')
    if bool(password) == bool(password_file):
        raise ValueError('Supply exactly one of KSPASS_FILE (preferred) or KSPASS')
    if password_file:
        path = external_file(password_file, 'KSPASS_FILE', output)
        # Do not print contents or turn them into command-line arguments.
        raw = path.read_bytes()
        if not raw or len(raw) > 4096 or raw.startswith(b'\xef\xbb\xbf'):
            raise ValueError('Password file must contain one UTF-8 line without BOM')
        try:
            raw.decode('utf-8')
        except UnicodeError:
            raise ValueError('Password file must use UTF-8') from None
        line = raw.rstrip(b'\r\n')
        if (not line or b'\r' in line or b'\n' in line or b'\x00' in line
                or raw not in (line, line+b'\n', line+b'\r\n')):
            raise ValueError('Password file must contain one nonempty line')
        source = 'file:' + str(path)
    else:
        if '\n' in password or '\r' in password or '\x00' in password:
            raise ValueError('KSPASS must contain one nonempty line')
        source = 'env:KSPASS'
    return key, source, fingerprint.upper()


def sdk_run(args, env):
    # SDK errors must not echo private input contents into CI logs.
    result = subprocess.run([str(x) for x in args], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise ValueError('SDK alignment/signing failed; no verified artifact was exported')


def sign(apk, source, output, sdk=None):
    stage = 'configuration'
    try:
        apk, source, output = Path(apk).resolve(), Path(source).resolve(), Path(output).resolve()
        if output.exists() or output in apk.parents or output in source.parents:
            raise ValueError('Signing output must be new and separate from inputs')
        if not apk.is_file() or not source.is_file():
            raise ValueError('Unsigned APK and approved Twitch input are required')
        env = dict(os.environ)
        key, password_source, expected = signing_config(env, output)
        tools = Path(sdk or env.get('ANDROID_SDK_ROOT', Path.home() / 'Android/Sdk')) / 'build-tools/30.0.3'
        # Without --key-pass, SDK first tries the store password for the key.
        # Do not read a one-line password file twice; stdin is closed if that fails.
        with tempfile.TemporaryDirectory(prefix='bttv-protected-sign-') as directory:
            work = Path(directory)
            aligned, signed = work / 'aligned.apk', work / 'signed.apk'
            stage = 'alignment'
            sdk_run([zipalign_tool(tools.parent.parent), '-P', '16', '4', apk, aligned], env)
            stage = 'signing'
            sdk_run([tools / 'apksigner', 'sign', '--ks', key, '--ks-key-alias', 'bttv-android',
                     '--ks-pass', password_source,
                     '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
                     '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false',
                     '--out', signed, aligned], env)
            stage = 'verification'
            proof = verify(signed, source, tools.parent.parent, expected, allow_test=False)
            stage = 'export'
            output.mkdir(parents=True)
            exported, partial = output / 'twitch.apk', output / 'twitch.apk.part'
            with signed.open('rb') as src, partial.open('xb') as dst:
                shutil.copyfileobj(src, dst)
            if sha256(partial) != proof['sha256']:
                raise ValueError('Export hash mismatch; do not use candidate')
            with (output / 'verification.json').open('x', encoding='utf-8') as stream:
                stream.write(json.dumps(proof, indent=2) + '\n')
            partial.rename(exported)
        print('Verified private-signed candidate; sha256=' + proof['sha256'])
        return proof
    except Exception as error:
        raise SigningFailure(stage, failure_category(stage, error)) from None


def main(argv=None):
    p = SafeArgumentParser(prog='sign_release.py', description=__doc__)
    p.add_argument('--apk', required=True, type=Path)
    p.add_argument('--input', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sdk', type=Path)
    a = p.parse_args(argv)
    try:
        sign(a.apk, a.input, a.output, a.sdk)
    except Exception as error:
        p.exit(1, failure_message(error))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
