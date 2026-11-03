"""Credential-free native packaging tests; SDK signatures are explicitly mocked.

Synthetic ZIP/ELF/DEX fixtures exercise verifier branches, not real APK signing.
Official zipalign and actual unsigned APK integration are checked separately.
"""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import apk_native_policy as native
import verify_release_apk as verifier


def elf(abi, align=None):
    bits, machine = (2, 183) if abi == 'arm64-v8a' else (1, 40)
    align = align or (16384 if bits == 2 else 4096)
    data = bytearray(160)
    data[:7] = b'\x7fELF' + bytes([bits, 1, 1])
    struct.pack_into('<HHI', data, 16, 3, machine, 1)
    if bits == 2:
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HHH', data, 52, 64, 56, 1)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 160, 160, align)
    else:
        struct.pack_into('<I', data, 28, 52)
        struct.pack_into('<HHH', data, 40, 52, 32, 1)
        struct.pack_into('<IIIIIIII', data, 52, 1, 0, 0, 0, 160, 160, 5, align)
    return bytes(data)


def dex(index, overflow=False):
    data = bytearray(112)
    data[:8] = b'dex\n035\0'
    if index == 7:
        data.extend(b'Lbttv/Data;')
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 88, 65536 if overflow else 1)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def add(z, name, data, alignment=1, compression=zipfile.ZIP_STORED):
    info = zipfile.ZipInfo(name)
    info.compress_type = compression
    padding = (-(z.fp.tell() + 30 + len(name.encode()))) % alignment
    if 0 < padding < 4:
        padding += alignment
    if padding:
        info.extra = struct.pack('<HH', 0xcafe, padding-4) + bytes(padding-4)
    z.writestr(info, data)


class ElfPolicy(unittest.TestCase):
    def test_arm64_16k_and_64k_and_armv7_4k(self):
        self.assertEqual(native.elf_alignment(elf('arm64-v8a'), 'arm64-v8a'), 16384)
        self.assertEqual(native.elf_alignment(elf('arm64-v8a', 65536), 'arm64-v8a'), 65536)
        self.assertEqual(native.elf_alignment(elf('armeabi-v7a'), 'armeabi-v7a'), 4096)

    def test_arm64_4k_is_not_16k(self):
        with self.assertRaisesRegex(ValueError, 'ELF load alignment'):
            native.elf_alignment(elf('arm64-v8a', 4096), 'arm64-v8a')

    def test_missing_truncated_and_incongruent_segments_rejected(self):
        for edit in ['count', 'offset', 'congruence', 'size', 'power']:
            data = bytearray(elf('arm64-v8a'))
            if edit == 'count': struct.pack_into('<H', data, 56, 0)
            if edit == 'offset': struct.pack_into('<Q', data, 32, 160)
            if edit == 'congruence': struct.pack_into('<Q', data, 80, 4096)
            if edit == 'size': struct.pack_into('<Q', data, 96, 161)
            if edit == 'power': struct.pack_into('<Q', data, 112, 24576)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                native.elf_alignment(data, 'arm64-v8a')

    def test_incorrect_architecture_and_unsupported_abi_rejected(self):
        with self.assertRaises(ValueError): native.elf_alignment(elf('armeabi-v7a'), 'arm64-v8a')
        with self.assertRaises(ValueError): native.elf_alignment(elf('arm64-v8a'), 'x86_64')


class FinalVerifier(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bttv-native-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'tools').mkdir()
        config = json.loads((ROOT/'bttv.manifest.json').read_text())
        (self.root/'bttv.manifest.json').write_text(json.dumps(config))
        pins = {'native': {'jni/'+abi+'/libglide-webp.so': {'sha256': hashlib.sha256(elf(abi)).hexdigest().upper()}
                           for abi in native.SUPPORTED_ABIS}}
        (self.root/'tools/webpdecoder-inputs.json').write_text(json.dumps(pins))
        self.calls = []
        self.cert = 'A'*64
        self.v3 = True
        self.source = self.root/'input.zip'
        with zipfile.ZipFile(self.source, 'w') as bundle:
            for abi, split in [('arm64-v8a', 'arm64_v8a'), ('armeabi-v7a', 'armeabi_v7a')]:
                output = io.BytesIO()
                with zipfile.ZipFile(output, 'w') as z:
                    for i in range(38): add(z, 'lib/'+abi+'/libstock%d.so'%i, elf(abi))
                bundle.writestr('split_config.'+split+'.apk', output.getvalue())

    def sdk(self, *args):
        args = list(map(str, args)); self.calls.append(args)
        if args[1:3] == ['dump', 'badging']:
            return ("package: name='tv.twitch.bttvandroid.app' versionCode='1208000341' versionName='0.44.2-beta'\n"
                    "sdkVersion:'29'\ntargetSdkVersion:'36'\n")
        if args[1:3] == ['dump', 'xmltree']:
            return 'android:extractNativeLibs=0x0\n' + '\n'.join('android:authorities="provider%d"'%i for i in range(9))
        if args[1] == 'verify':
            return 'Verified using v3 scheme: '+str(self.v3).lower()+'\ncertificate SHA-256 digest: '+self.cert
        return ''  # Deliberately claim SDK alignment passed; independent ZIP check must still reject bad offsets.

    def apk(self, alignment=16384, compression=zipfile.ZIP_STORED, arm64_align=16384,
            extra=None, corrupt_stock=False, corrupt_decoder=False, overflow=False):
        p = self.root/'fixture.zip'
        with zipfile.ZipFile(p, 'w') as z:
            for i in range(1, 8): add(z, 'classes.dex' if i == 1 else 'classes%d.dex'%i, dex(i, overflow and i == 7))
            for n in ['bttv_third_party_notices.txt', 'bttv_apksig_license.txt']: add(z, 'res/raw/'+n, b'fixture notice')
            for abi in native.SUPPORTED_ABIS:
                for name in ['libstock%d.so'%i for i in range(38)] + ['libglide-webp.so']:
                    data = bytearray(elf(abi, arm64_align if abi == 'arm64-v8a' else 4096))
                    if corrupt_stock and name == 'libstock0.so': data[-1] = 1
                    if corrupt_decoder and name == 'libglide-webp.so': data[-1] = 1
                    add(z, 'lib/'+abi+'/'+name, data, alignment, compression)
            if extra: add(z, extra, elf('arm64-v8a'), alignment)
        return p

    def verify(self, **kwargs):
        with patch.object(verifier, 'ROOT', self.root), patch.object(verifier, 'run', side_effect=self.sdk), patch('prepare_twitch_input.inspect'):
            return verifier.verify(self.apk(**kwargs), self.source, self.root/'sdk', 'A'*64)

    def test_final_path_enforces_16k_and_retains_sdk30_crypto(self):
        result = self.verify()
        self.assertEqual(result['native'], {'arm64-v8a': 39, 'armeabi-v7a': 39})
        self.assertEqual(result['nativeZipAlignment'], 16384)
        self.assertEqual(result['nativeElfAlignment'], {'arm64-v8a': 16384, 'armeabi-v7a': 4096})
        self.assertEqual(self.calls[-1][0], str(self.root/'sdk/build-tools/35.0.0/zipalign'))
        self.assertEqual(self.calls[-1][1:5], ['-c', '-P', '16', '4'])
        self.assertTrue(all(Path(call[0]).parent.name == '30.0.3' for call in self.calls[:-1]))

    def test_4k_zip_rejected_even_if_sdk_check_reports_success(self):
        with self.assertRaisesRegex(ValueError, 'compression/alignment'): self.verify(alignment=4096)

    def test_compressed_native_rejected(self):
        with self.assertRaisesRegex(ValueError, 'compression/alignment'): self.verify(compression=zipfile.ZIP_DEFLATED)

    def test_16k_zip_cannot_mask_incompatible_elf(self):
        with self.assertRaisesRegex(ValueError, 'ELF load alignment'): self.verify(arm64_align=4096)

    def test_decoder_only_x86_and_unknown_abi_rejected(self):
        for abi in ['x86', 'x86_64', 'armeabi', 'unknown']:
            with self.subTest(abi=abi), self.assertRaisesRegex(ValueError, 'Unexpected native ABI'):
                self.verify(extra='lib/'+abi+'/libglide-webp.so')

    def test_original_twitch_payload_comparison_not_weakened(self):
        with self.assertRaisesRegex(ValueError, 'Original Twitch native library changed'): self.verify(corrupt_stock=True)

    def test_old_or_modified_decoder_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unexpected WebP decoder'): self.verify(corrupt_decoder=True)

    def test_certificate_v3_and_dex_limits_remain_required(self):
        self.cert = 'B'*64
        with self.assertRaisesRegex(ValueError, 'signing certificate'): self.verify()
        self.cert = 'A'*64; self.v3 = False
        with self.assertRaisesRegex(ValueError, 'v3 signature'): self.verify()
        self.v3 = True
        with self.assertRaisesRegex(ValueError, 'DEX pool'): self.verify(overflow=True)


class Configuration(unittest.TestCase):
    def test_consumer_abi_filter_and_distinct_sdk_roles(self):
        source = (ROOT/'mod/consumer/build.gradle').read_text()
        self.assertIn("ndk { abiFilters 'arm64-v8a', 'armeabi-v7a' }", source)
        self.assertIn('buildToolsVersion "30.0.3"', source)
        docker = (ROOT/'Dockerfile').read_text()
        self.assertIn('"build-tools;30.0.3"', docker)
        self.assertIn('build-tools/35.0.0', docker)
        self.assertIn('bd3a4966912eb8b30ed0d00b0cda6b6543b949d5ffe00bea54c04c81e1561d88', docker)
        self.assertEqual(native.zipalign_tool('/sdk'), Path('/sdk/build-tools/35.0.0/zipalign'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
