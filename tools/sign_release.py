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

from verify_release_apk import ROOT, TEST_SIGNER, sha256, verify


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
        sdk_run([tools / 'zipalign', '-p', '4', apk, aligned], env)
        sdk_run([tools / 'apksigner', 'sign', '--ks', key, '--ks-key-alias', 'bttv-android',
                 '--ks-pass', password_source,
                 '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
                 '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false',
                 '--out', signed, aligned], env)
        proof = verify(signed, source, tools.parent.parent, expected, allow_test=False)
        output.mkdir(parents=True)
        exported, partial = output / 'twitch.apk', output / 'twitch.apk.part'
        with signed.open('rb') as src, partial.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        if sha256(partial) != proof['sha256']:
            raise ValueError('Export hash mismatch; do not use candidate')
        with (output / 'verification.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(proof, indent=2) + '\n')
        partial.rename(exported)
    print('Verified private-signed candidate:', exported, proof['sha256'])
    return proof


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk', required=True, type=Path)
    p.add_argument('--input', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sdk', type=Path)
    a = p.parse_args()
    try:
        sign(a.apk, a.input, a.output, a.sdk)
    except Exception:
        # Avoid unfiltered SDK/keystore/password-parser messages or tracebacks.
        p.exit(1, 'Protected signing/verification failed; no candidate is approved. Check private inputs and certificate pin.\n')
