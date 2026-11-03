"""Offline WebP dependency security, binary-parser and compatibility regressions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('webp_inspection', ROOT/'tools/verify_webp_decoder.py')
webp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(webp)


class WebpPolicy(unittest.TestCase):
    def test_glide_is_strictly_retained_and_decoder_transitive_glide_excluded(self):
        source = (ROOT/'mod/app/build.gradle').read_text()
        self.assertIn('def GLIDE_VERSION = "4.12.0"', source)
        self.assertIn("api('com.github.zjupure:webpdecoder:2.7.4.16.0')", source)
        self.assertIn("exclude group: 'com.github.bumptech.glide', module: 'glide'", source)
        self.assertIn('api("com.github.bumptech.glide:glide:${GLIDE_VERSION}")', source)
        self.assertIn('version { strictly GLIDE_VERSION }', source)
        self.assertNotIn('webpdecoder:2.0.', source)

    def test_pinned_official_inputs_and_both_arm_architectures(self):
        policy = json.loads(webp.MANIFEST.read_text())
        self.assertEqual(policy['coordinate'], 'com.github.zjupure:webpdecoder:2.7.4.16.0')
        self.assertEqual(policy['libwebpVersion'], '1.3.2')
        self.assertEqual(policy['glideVersion'], '4.12.0')
        self.assertEqual(policy['packagedAbis'], ['arm64-v8a', 'armeabi-v7a'])
        self.assertEqual(policy['upstreamRevision'], '56d3f2523d546bd069600b8ee2435a0e0e2c3c07')
        for item in policy['artifacts'].values():
            self.assertTrue(item['url'].startswith('https://repo.maven.apache.org/maven2/'))
            self.assertRegex(item['sha256'], r'^[0-9A-F]{64}$')
        for abi, bits, machine in [('arm64-v8a', 64, 183), ('armeabi-v7a', 32, 40)]:
            info = policy['native']['jni/'+abi+'/libglide-webp.so']
            self.assertEqual((info['bits'], info['machine'], info['version']), (bits, machine, '1.3.2'))
            self.assertTrue(info['loads'])
            if bits == 64:
                self.assertTrue(all(p['align'] >= 16384 for p in info['loads']))

    def test_notices_retain_licenses_and_record_correct_native_version(self):
        notice = (ROOT/'mod/app/src/main/res/raw/bttv_third_party_notices.txt').read_text()
        doc = (ROOT/'THIRD_PARTY_NOTICES.md').read_text()
        for text in [notice, doc]:
            self.assertIn('2.7.4.16.0', text)
            self.assertIn('1.3.2', text)
            self.assertIn('56d3f2523d546bd069600b8ee2435a0e0e2c3c07', text)
            self.assertNotIn('snapshot identifies libwebp 1.1.0', text)
        self.assertIn('libwebp COPYING', notice)
        self.assertIn('libwebp additional patent grant', notice)
        self.assertIn('Copyright (c) 2010, Google Inc. All rights reserved.', notice)
        self.assertIn('Copyright 2017-2018 zjupure', notice)

    def test_existing_animation_adapter_still_starts_stops_and_rebinds(self):
        source = (ROOT/'mod/app/src/main/java/bttv/glide/Webp.java').read_text()
        for operation in ['registerComponents(context, glide, registry)', 'webpDrawable.setCallback(cb)',
                          'webpDrawable.start()', 'webpDrawable.stop()']:
            self.assertIn(operation, source)
        provenance = (ROOT/'mod/app/libs/NOTICE-webpdecoder.md').read_text()
        self.assertIn('Physical-device animation testing remains required', provenance)
        self.assertIn('not a vendor-published', provenance)

    def test_remediation_inverse_preserves_all_other_source_and_notices(self):
        for path in _WEBP_EDITS:
            old = subprocess.check_output(['git', 'show', '8a5ddeea8a00a2800b294594699dfa3ed16e3e09:' + path], cwd=ROOT).decode()
            self.assertEqual(before_webp_remediation(path, (ROOT/path).read_text()), old)


class BinaryInspection(unittest.TestCase):
    def test_corrupt_elf_and_class_rejected(self):
        for data in [b'', b'\x7fELF', bytes(64), b'\x7fELF'+bytes(60)]:
            with self.subTest(data=data[:4]), self.assertRaises(ValueError):
                webp.elf(data)
        with self.assertRaises(ValueError):
            webp.class_file(b'bad class')

    def test_hash_mismatch_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/'fixture'
            p.write_bytes(b'fixture')
            webp.checked_hash(p, hashlib.sha256(b'fixture').hexdigest().upper())
            with self.assertRaises(ValueError):
                webp.checked_hash(p, '0'*64)

    def test_linkage_checks_descriptors_and_inherited_methods(self):
        def cls(superclass=None, methods=(), refs=()):
            return dict(super=superclass, interfaces=[], fields=set(), methods=set(methods), refs=set(refs))
        parent = 'com/bumptech/glide/Base'
        child = 'com/bumptech/glide/Child'
        decoder = {'Wrapper': cls(refs=[(10, child, 'start', '()V')])}
        glide = {child: cls(parent), parent: cls(methods=[('start', '()V')])}
        self.assertEqual(webp.linkage(decoder, glide), (1, []))
        glide[parent]['methods'] = {('start', '(I)V')}
        self.assertEqual(webp.linkage(decoder, glide)[1], [(child, 'start', '()V')])

    def test_constructors_are_not_inherited(self):
        parent = 'com/bumptech/glide/Base'
        child = 'com/bumptech/glide/Child'
        decoder = {'Wrapper': dict(super=None, interfaces=[], fields=set(), methods=set(),
                                  refs={(10, child, '<init>', '()V')})}
        glide = {parent: dict(super=None, interfaces=[], fields=set(), methods={('<init>', '()V')}),
                 child: dict(super=parent, interfaces=[], fields=set(), methods=set())}
        self.assertEqual(webp.linkage(decoder, glide)[1], [(child, '<init>', '()V')])


# Exact inverse of the reviewed dependency/notice changes, for older freeze tests.
# Any unrelated change still fails their original byte/text comparison.
_WEBP_EDITS = {'mod/app/build.gradle': [('    def GLIDE_VERSION = "4.12.0"\n'
                           "    implementation 'androidx.appcompat:appcompat:1.2.0'\n"
                           "    implementation 'com.google.android.material:material:1.3.0'\n"
                           '    api "com.github.zjupure:webpdecoder:2.0.${GLIDE_VERSION}"\n'
                           '    api "com.caverock:androidsvg-aar:1.4"\n'
                           "    implementation project(path: ':twitch')\n"
                           "    testImplementation 'junit:junit:4.+'\n",
                           '    def GLIDE_VERSION = "4.12.0"\n'
                           "    implementation 'androidx.appcompat:appcompat:1.2.0'\n"
                           "    implementation 'com.google.android.material:material:1.3.0'\n"
                           "    // Verified against Glide 4.12.0; do not transitively upgrade Twitch's Glide.\n"
                           '    // Artifact/native hashes and compatibility evidence: '
                           'libs/NOTICE-webpdecoder.md.\n'
                           "    api('com.github.zjupure:webpdecoder:2.7.4.16.0') {\n"
                           "        exclude group: 'com.github.bumptech.glide', module: 'glide'\n"
                           '    }\n'
                           '    api("com.github.bumptech.glide:glide:${GLIDE_VERSION}") {\n'
                           '        version { strictly GLIDE_VERSION }\n'
                           '    }\n'
                           '    api "com.caverock:androidsvg-aar:1.4"\n'
                           "    implementation project(path: ':twitch')\n"
                           "    testImplementation 'junit:junit:4.+'\n")],
 'mod/consumer/build.gradle': [('        targetSdkVersion 30\n'
                                '        versionCode 1\n'
                                '        versionName "1.0"\n'
                                '\n'
                                '        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"\n'
                                '    }\n',
                                '        targetSdkVersion 30\n'
                                '        versionCode 1\n'
                                '        versionName "1.0"\n'
                                '\n'
                                '        // Match the pinned Twitch input; decoder-only x86 is not an app ABI.\n'
                                "        ndk { abiFilters 'arm64-v8a', 'armeabi-v7a' }\n"
                                '\n'
                                '        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"\n'
                                '    }\n')],
 'THIRD_PARTY_NOTICES.md': [('| JetBrains annotations | 13.0 | Apache-2.0; [artifact '
                             'metadata](https://repo.maven.apache.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.pom) '
                             '|\n'
                             '| Public Suffix List data in OkHttp | Snapshot specified below | MPL-2.0; notice '
                             'and preferred source below |\n'
                             '| Glide, gifdecoder, disklrucache and annotations | 4.12.0 | Composite BSD-style, '
                             'MIT and Apache-2.0 terms; [complete upstream '
                             'license](https://github.com/bumptech/glide/blob/v4.12.0/LICENSE), reproduced in the '
                             'bundled notice |\n'
                             '| GlideWebpDecoder | 2.0.4.12.0 | Apache-2.0 wrapper, Copyright 2017-2018 zjupure; '
                             '[pinned '
                             'source](https://github.com/zjupure/GlideWebpDecoder/tree/989e6a4ab7db933c7685d40ee1047fcddeb4c4e5) '
                             '|\n'
                             '| libwebp in GlideWebpDecoder | Provider snapshot identifies 1.1.0 | Google '
                             'BSD-style terms and additional patent grant; '
                             '[COPYING](https://github.com/webmproject/libwebp/blob/v1.1.0/COPYING), '
                             '[PATENTS](https://github.com/webmproject/libwebp/blob/v1.1.0/PATENTS) reproduced in '
                             'the bundled notice |\n'
                             '| AndroidSVG | 1.4 | Apache-2.0, Copyright 2013-2018 Cave Rock Software Ltd; '
                             '[pinned '
                             'license](https://github.com/BigBadaboom/androidsvg/blob/9490d751d91033051efc6a4a9835ceff6082e9ff/LICENSE) '
                             '|\n'
                             '| AndroidX libraries and Material Components | Resolved consumer inventory below | '
                             'Apache-2.0; Android Open Source Project / respective contributors; [AndroidX '
                             'license](https://android.googlesource.com/platform/frameworks/support/+/androidx-main/LICENSE.txt), '
                             '[Material '
                             'license](https://github.com/material-components/material-components-android/blob/1.4.0/LICENSE) '
                             '|\n'
                             '\n',
                             '| JetBrains annotations | 13.0 | Apache-2.0; [artifact '
                             'metadata](https://repo.maven.apache.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.pom) '
                             '|\n'
                             '| Public Suffix List data in OkHttp | Snapshot specified below | MPL-2.0; notice '
                             'and preferred source below |\n'
                             '| Glide, gifdecoder, disklrucache and annotations | 4.12.0 | Composite BSD-style, '
                             'MIT and Apache-2.0 terms; [complete upstream '
                             'license](https://github.com/bumptech/glide/blob/v4.12.0/LICENSE), reproduced in the '
                             'bundled notice |\n'
                             '| GlideWebpDecoder | 2.7.4.16.0, with Glide retained at 4.12.0 | Apache-2.0 '
                             'wrapper, Copyright 2017-2018 zjupure; [pinned '
                             'source](https://github.com/zjupure/GlideWebpDecoder/tree/56d3f2523d546bd069600b8ee2435a0e0e2c3c07), '
                             '[artifact/compatibility provenance](mod/app/libs/NOTICE-webpdecoder.md) |\n'
                             '| libwebp in GlideWebpDecoder | 1.3.2, confirmed in both ARM binaries | Google '
                             'BSD-style terms and additional patent grant; '
                             '[COPYING](https://github.com/webmproject/libwebp/blob/v1.3.2/COPYING), '
                             '[PATENTS](https://github.com/webmproject/libwebp/blob/v1.3.2/PATENTS) reproduced in '
                             'the bundled notice |\n'
                             '| AndroidSVG | 1.4 | Apache-2.0, Copyright 2013-2018 Cave Rock Software Ltd; '
                             '[pinned '
                             'license](https://github.com/BigBadaboom/androidsvg/blob/9490d751d91033051efc6a4a9835ceff6082e9ff/LICENSE) '
                             '|\n'
                             '| AndroidX libraries and Material Components | Resolved consumer inventory below | '
                             'Apache-2.0; Android Open Source Project / respective contributors; [AndroidX '
                             'license](https://android.googlesource.com/platform/frameworks/support/+/androidx-main/LICENSE.txt), '
                             '[Material '
                             'license](https://github.com/material-components/material-components-android/blob/1.4.0/LICENSE) '
                             '|\n'
                             '\n')],
 'mod/app/src/main/res/raw/bttv_third_party_notices.txt': [('  JetBrains annotations 13.0.\n'
                                                            '  https://github.com/JetBrains/kotlin/tree/v1.9.10\n'
                                                            '  '
                                                            'https://repo.maven.apache.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.pom\n'
                                                            '- GlideWebpDecoder 2.0.4.12.0 wrapper: Copyright '
                                                            '2017-2018 zjupure.\n'
                                                            '  '
                                                            'https://github.com/zjupure/GlideWebpDecoder/tree/989e6a4ab7db933c7685d40ee1047fcddeb4c4e5\n'
                                                            '- AndroidSVG 1.4: Copyright 2013-2018 Cave Rock '
                                                            'Software Ltd.\n'
                                                            '  '
                                                            'https://github.com/BigBadaboom/androidsvg/tree/9490d751d91033051efc6a4a9835ceff6082e9ff\n'
                                                            '- AndroidX libraries and Material Components: '
                                                            'Android Open Source Project and\n',
                                                            '  JetBrains annotations 13.0.\n'
                                                            '  https://github.com/JetBrains/kotlin/tree/v1.9.10\n'
                                                            '  '
                                                            'https://repo.maven.apache.org/maven2/org/jetbrains/annotations/13.0/annotations-13.0.pom\n'
                                                            '- GlideWebpDecoder 2.7.4.16.0 wrapper: Copyright '
                                                            '2017-2018 zjupure.\n'
                                                            '  '
                                                            'https://github.com/zjupure/GlideWebpDecoder/tree/56d3f2523d546bd069600b8ee2435a0e0e2c3c07\n'
                                                            "  Glide remains 4.12.0; the decoder's transitive "
                                                            'Glide 4.16.0 is excluded.\n'
                                                            '- AndroidSVG 1.4: Copyright 2013-2018 Cave Rock '
                                                            'Software Ltd.\n'
                                                            '  '
                                                            'https://github.com/BigBadaboom/androidsvg/tree/9490d751d91033051efc6a4a9835ceff6082e9ff\n'
                                                            '- AndroidX libraries and Material Components: '
                                                            'Android Open Source Project and\n'),
                                                           ('\n'
                                                            'Glide 4.12.0 and its gifdecoder/disklrucache '
                                                            'components carry the composite license\n'
                                                            'below. The decoder includes separate libwebp '
                                                            'BSD-style terms and a patent grant.\n'
                                                            'The provider source snapshot identifies libwebp '
                                                            '1.1.0; exact native compilation\n'
                                                            'reproducibility is not asserted. No local decoder '
                                                            'library-source fork is made.\n'
                                                            '\n'
                                                            'Public Suffix List data: MPL 2.0, separate from the '
                                                            'Apache-licensed HTTP code.\n'
                                                            'License: https://www.mozilla.org/en-US/MPL/2.0/\n',
                                                            '\n'
                                                            'Glide 4.12.0 and its gifdecoder/disklrucache '
                                                            'components carry the composite license\n'
                                                            'below. The decoder includes separate libwebp '
                                                            'BSD-style terms and a patent grant.\n'
                                                            'Both ARM decoder binaries report libwebp 1.3.2. '
                                                            'Artifact hashes and compatibility\n'
                                                            'evidence are recorded in '
                                                            'mod/app/libs/NOTICE-webpdecoder.md and\n'
                                                            'tools/webpdecoder-inputs.json. Exact native '
                                                            'compilation reproducibility is not\n'
                                                            'asserted. No local decoder library-source fork is '
                                                            'made.\n'
                                                            '\n'
                                                            'Public Suffix List data: MPL 2.0, separate from the '
                                                            'Apache-licensed HTTP code.\n'
                                                            'License: https://www.mozilla.org/en-US/MPL/2.0/\n')],
 'tools/sign_release.py': [('import zipfile\n'
                            '\n'
                            'from verify_release_apk import ROOT, TEST_SIGNER, sha256, verify\n'
                            '\n'
                            '\n'
                            '# Only these literal tokens may reach failure output. Never interpolate an\n',
                            'import zipfile\n'
                            '\n'
                            'from verify_release_apk import ROOT, TEST_SIGNER, sha256, verify\n'
                            'from apk_native_policy import zipalign_tool\n'
                            '\n'
                            '\n'
                            '# Only these literal tokens may reach failure output. Never interpolate an\n'),
                           ("                'BTTV injection missing from classes7.dex': 'DEX_INVALID',\n"
                            "                'Missing packaged license resource': 'NOTICES_MISSING',\n"
                            "                'Native architecture mismatch': 'NATIVE_INVALID',\n"
                            "                'Incomplete dual-ARM inventory': 'NATIVE_INVALID',\n"
                            "                'Original Twitch native library changed': 'NATIVE_INVALID',\n"
                            '            }\n',
                            "                'BTTV injection missing from classes7.dex': 'DEX_INVALID',\n"
                            "                'Missing packaged license resource': 'NOTICES_MISSING',\n"
                            "                'Native architecture mismatch': 'NATIVE_INVALID',\n"
                            "                'Unexpected native ABI': 'NATIVE_INVALID',\n"
                            "                'Native ELF load alignment failure': 'NATIVE_INVALID',\n"
                            "                'Unexpected WebP decoder': 'NATIVE_INVALID',\n"
                            "                'Incomplete dual-ARM inventory': 'NATIVE_INVALID',\n"
                            "                'Original Twitch native library changed': 'NATIVE_INVALID',\n"
                            '            }\n'),
                           ('            work = Path(directory)\n'
                            "            aligned, signed = work / 'aligned.apk', work / 'signed.apk'\n"
                            "            stage = 'alignment'\n"
                            "            sdk_run([tools / 'zipalign', '-p', '4', apk, aligned], env)\n"
                            "            stage = 'signing'\n"
                            "            sdk_run([tools / 'apksigner', 'sign', '--ks', key, '--ks-key-alias', "
                            "'bttv-android',\n"
                            "                     '--ks-pass', password_source,\n",
                            '            work = Path(directory)\n'
                            "            aligned, signed = work / 'aligned.apk', work / 'signed.apk'\n"
                            "            stage = 'alignment'\n"
                            "            sdk_run([zipalign_tool(tools.parent.parent), '-P', '16', '4', apk, "
                            'aligned], env)\n'
                            "            stage = 'signing'\n"
                            "            sdk_run([tools / 'apksigner', 'sign', '--ks', key, '--ks-key-alias', "
                            "'bttv-android',\n"
                            "                     '--ks-pass', password_source,\n")],
 'tools/verify_release_apk.py': [('import subprocess\n'
                                  'import zipfile\n'
                                  'import zlib\n'
                                  '\n'
                                  'TEST_SIGNER = '
                                  '"1E08A903AEF9C3A721510B64EC764D01D3D094EB954161B62544EA8F187B5953"\n'
                                  'ROOT = Path(__file__).resolve().parents[1]\n',
                                  'import subprocess\n'
                                  'import zipfile\n'
                                  'import zlib\n'
                                  'from apk_native_policy import (NATIVE_ZIP_ALIGNMENT, SUPPORTED_ABIS,\n'
                                  '                               ZIPALIGN_BUILD_TOOLS, check_native_entry, '
                                  'zipalign_tool)\n'
                                  '\n'
                                  'TEST_SIGNER = '
                                  '"1E08A903AEF9C3A721510B64EC764D01D3D094EB954161B62544EA8F187B5953"\n'
                                  'ROOT = Path(__file__).resolve().parents[1]\n'),
                                 ('        raise ValueError("Unexpected signing certificate")\n'
                                  '    if signer == TEST_SIGNER and not allow_test:\n'
                                  '        raise ValueError("Public bundled debug key is not a production signing '
                                  'identity")\n'
                                  '    alignment = run(tools / "zipalign", "-c", "-p", "4", apk)\n'
                                  '    dex_counts, native_counts = {}, {}\n'
                                  '    with zipfile.ZipFile(apk) as z, apk.open("rb") as raw:\n'
                                  '        names = z.namelist()\n'
                                  '        if len(names) != len(set(names)) or z.testzip():\n',
                                  '        raise ValueError("Unexpected signing certificate")\n'
                                  '    if signer == TEST_SIGNER and not allow_test:\n'
                                  '        raise ValueError("Public bundled debug key is not a production signing '
                                  'identity")\n'
                                  '    alignment = run(zipalign_tool(sdk), "-c", "-P", "16", "4", apk)\n'
                                  '    dex_counts, native_counts, native_elf_alignment = {}, {}, {}\n'
                                  '    decoder_pins = json.loads((ROOT / '
                                  "'tools/webpdecoder-inputs.json').read_text())['native']\n"
                                  '    with zipfile.ZipFile(apk) as z, apk.open("rb") as raw:\n'
                                  '        names = z.namelist()\n'
                                  '        if len(names) != len(set(names)) or z.testzip():\n'),
                                 ('            if not z.read("res/raw/" + notice):\n'
                                  '                raise ValueError("Missing packaged license resource")\n'
                                  '        for entry in z.infolist():\n'
                                  '            if not entry.filename.startswith("lib/") or not '
                                  'entry.filename.endswith(".so"):\n'
                                  '                continue\n'
                                  "            abi = entry.filename.split('/')[1]\n"
                                  '            native_counts[abi] = native_counts.get(abi, 0) + 1\n'
                                  '            raw.seek(entry.header_offset)\n'
                                  '            header = raw.read(30)\n'
                                  "            filename_size, extra_size = struct.unpack_from('<HH', header, 26)\n"
                                  '            offset = entry.header_offset + 30 + filename_size + extra_size\n'
                                  '            if entry.compress_type != zipfile.ZIP_STORED or offset % 4096:\n'
                                  '                raise ValueError("Native compression/alignment failure: " + '
                                  'entry.filename)\n'
                                  '            data = z.read(entry)\n'
                                  "            if data[:4] != b'\\x7fELF' or len(data) < 64:\n"
                                  '                raise ValueError("Invalid native ELF: " + entry.filename)\n'
                                  "            if abi in ['arm64-v8a', 'armeabi-v7a']:\n"
                                  "                elf = (data[4], data[5], struct.unpack_from('<H', data, "
                                  '18)[0])\n'
                                  "                if elf != ((2, 1, 183) if abi == 'arm64-v8a' else (1, 1, "
                                  '40)):\n'
                                  '                    raise ValueError("Native architecture mismatch")\n'
                                  "        for abi in ['arm64-v8a', 'armeabi-v7a']:\n"
                                  "            if native_counts.get(abi) != 39 or 'lib/' + abi + "
                                  "'/libglide-webp.so' not in names:\n"
                                  '                raise ValueError("Incomplete dual-ARM inventory")\n',
                                  '            if not z.read("res/raw/" + notice):\n'
                                  '                raise ValueError("Missing packaged license resource")\n'
                                  '        for entry in z.infolist():\n'
                                  "            if entry.filename.startswith('lib/') and entry.filename != "
                                  "'lib/':\n"
                                  "                if entry.filename.split('/')[1] not in SUPPORTED_ABIS:\n"
                                  "                    raise ValueError('Unexpected native ABI')\n"
                                  '            if not entry.filename.startswith("lib/") or not '
                                  'entry.filename.endswith(".so"):\n'
                                  '                continue\n'
                                  '            abi, elf_align = check_native_entry(entry, raw, z.read(entry))\n'
                                  "            if entry.filename == 'lib/' + abi + '/libglide-webp.so':\n"
                                  "                expected_decoder = decoder_pins['jni/' + abi + "
                                  "'/libglide-webp.so']['sha256']\n"
                                  '                if hashlib.sha256(z.read(entry)).hexdigest().upper() != '
                                  'expected_decoder:\n'
                                  "                    raise ValueError('Unexpected WebP decoder')\n"
                                  '            native_counts[abi] = native_counts.get(abi, 0) + 1\n'
                                  '            native_elf_alignment[abi] = min(native_elf_alignment.get(abi, '
                                  'elf_align), elf_align)\n'
                                  "        for abi in ['arm64-v8a', 'armeabi-v7a']:\n"
                                  "            if native_counts.get(abi) != 39 or 'lib/' + abi + "
                                  "'/libglide-webp.so' not in names:\n"
                                  '                raise ValueError("Incomplete dual-ARM inventory")\n'),
                                 ('                targetSdk=target, signerSha256=signer, sha256=sha256(apk), '
                                  'sizeBytes=apk.stat().st_size,\n'
                                  "                standalone=True, supportedAbis=['arm64-v8a', 'armeabi-v7a'], "
                                  "twitchVersion='31.2.0',\n"
                                  '                dex=dex_counts, native=native_counts, authorities=authorities, '
                                  'v3=True, zipalign=True,\n'
                                  '                testSigningIdentity=(signer == TEST_SIGNER))\n'
                                  '\n'
                                  '\n',
                                  '                targetSdk=target, signerSha256=signer, sha256=sha256(apk), '
                                  'sizeBytes=apk.stat().st_size,\n'
                                  "                standalone=True, supportedAbis=['arm64-v8a', 'armeabi-v7a'], "
                                  "twitchVersion='31.2.0',\n"
                                  '                dex=dex_counts, native=native_counts, authorities=authorities, '
                                  'v3=True, zipalign=True,\n'
                                  '                nativeZipAlignment=NATIVE_ZIP_ALIGNMENT, '
                                  'nativeElfAlignment=native_elf_alignment,\n'
                                  '                zipalignBuildTools=ZIPALIGN_BUILD_TOOLS,\n'
                                  '                testSigningIdentity=(signer == TEST_SIGNER))\n'
                                  '\n'
                                  '\n')],
 'tools/build_production.py': [('    "tools/build_production.py", "tools/docker_build.sh",\n'
                                '    "tools/prepare_twitch_input.py", "tools/twitch-31.2.0-inputs.json",\n'
                                '    "tools/verify_release_apk.py", "tools/release_metadata.py",\n'
                                '    "tests/stage9_infrastructure.py", "RELEASING.md",\n'
                                ')\n'
                                '\n',
                                '    "tools/build_production.py", "tools/docker_build.sh",\n'
                                '    "tools/prepare_twitch_input.py", "tools/twitch-31.2.0-inputs.json",\n'
                                '    "tools/verify_release_apk.py", "tools/release_metadata.py",\n'
                                '    "tools/apk_native_policy.py",\n'
                                '    "tools/webpdecoder-inputs.json",\n'
                                '    "tests/stage9_infrastructure.py", "RELEASING.md",\n'
                                ')\n'
                                '\n')],
 'Dockerfile': [('    unzip -q commandlinetools.zip && rm commandlinetools.zip && \\\n'
                 '    yes | /opt/cmdline-tools/bin/sdkmanager --sdk_root="$ANDROID_SDK_ROOT" \\\n'
                 '    "build-tools;30.0.3" "platforms;android-30"\n'
                 '\n'
                 'RUN curl --fail --location --retry 3 -o apktool_2.9.3.jar \\\n'
                 '    https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar && \\\n',
                 '    unzip -q commandlinetools.zip && rm commandlinetools.zip && \\\n'
                 '    yes | /opt/cmdline-tools/bin/sdkmanager --sdk_root="$ANDROID_SDK_ROOT" \\\n'
                 '    "build-tools;30.0.3" "platforms;android-30"\n'
                 '\n'
                 '# Dedicated official -P 16 zipalign. Gradle, aapt and apksigner stay on 30.0.3.\n'
                 '# Google repository index SHA-1: 2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc.\n'
                 'RUN curl --fail --location --retry 3 -o build-tools_r35_linux.zip \\\n'
                 '    https://dl.google.com/android/repository/build-tools_r35_linux.zip && \\\n'
                 "    echo 'bd3a4966912eb8b30ed0d00b0cda6b6543b949d5ffe00bea54c04c81e1561d88  "
                 "build-tools_r35_linux.zip' | sha256sum -c - && \\\n"
                 '    unzip -q build-tools_r35_linux.zip -d "$ANDROID_SDK_ROOT/build-tools" && \\\n'
                 '    mv "$ANDROID_SDK_ROOT/build-tools/android-15" "$ANDROID_SDK_ROOT/build-tools/35.0.0" && \\\n'
                 '    rm build-tools_r35_linux.zip\n'
                 '\n'
                 'RUN curl --fail --location --retry 3 -o apktool_2.9.3.jar \\\n'
                 '    https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar && \\\n')],
 '.github/workflows/docker.yml': [('      - .dockerignore\n'
                                   '      - compose.yaml\n'
                                   '      - tools/docker_build.sh\n'
                                   '      - .github/workflows/docker.yml\n'
                                   '  workflow_dispatch: {}\n'
                                   '\n',
                                   '      - .dockerignore\n'
                                   '      - compose.yaml\n'
                                   '      - tools/docker_build.sh\n'
                                   '      - tools/apk_native_policy.py\n'
                                   '      - tests/community_native_packaging.py\n'
                                   '      - .github/workflows/docker.yml\n'
                                   '  workflow_dispatch: {}\n'
                                   '\n'),
                                  ('            java -version\n'
                                   '            python3 --version\n'
                                   '            test -x "$ANDROID_SDK_ROOT/build-tools/30.0.3/zipalign"\n'
                                   '            test -f "$ANDROID_SDK_ROOT/platforms/android-30/android.jar"\n'
                                   '            # APKEditor 1.4.9 returns 2 for informational commands.\n'
                                   '            if apkeditor_version=$(java -jar "$APKEDITOR_PATH" -version '
                                   '2>&1); then\n',
                                   '            java -version\n'
                                   '            python3 --version\n'
                                   '            test -x "$ANDROID_SDK_ROOT/build-tools/30.0.3/zipalign"\n'
                                   '            test -x "$ANDROID_SDK_ROOT/build-tools/35.0.0/zipalign"\n'
                                   '            test -f "$ANDROID_SDK_ROOT/platforms/android-30/android.jar"\n'
                                   '            # APKEditor 1.4.9 returns 2 for informational commands.\n'
                                   '            if apkeditor_version=$(java -jar "$APKEDITOR_PATH" -version '
                                   '2>&1); then\n'),
                                  ('              exit 1\n'
                                   '            fi\n'
                                   '            printf "%s\\n" "$apkeditor_version"\n'
                                   "          '\n",
                                   '              exit 1\n'
                                   '            fi\n'
                                   '            printf "%s\\n" "$apkeditor_version"\n'
                                   '            probe_dir=$(mktemp -d)\n'
                                   '            mkdir -p "$probe_dir/lib/arm64-v8a"\n'
                                   '            printf probe > "$probe_dir/lib/arm64-v8a/probe.so"\n'
                                   '            (cd "$probe_dir" && zip -0 -q probe-unaligned.apk '
                                   'lib/arm64-v8a/probe.so)\n'
                                   '            "$ANDROID_SDK_ROOT/build-tools/35.0.0/zipalign" -P 16 4 '
                                   '"$probe_dir/probe-unaligned.apk" "$probe_dir/probe-aligned.apk"\n'
                                   '            "$ANDROID_SDK_ROOT/build-tools/35.0.0/zipalign" -c -P 16 4 '
                                   '"$probe_dir/probe-aligned.apk"\n'
                                   "          '\n")],
 '.github/workflows/ci.yml': [('          python3 tests/stage9_infrastructure.py\n'
                               '          python3 tests/community_updater.py\n'
                               '          python3 tests/community_signing.py\n'
                               '      - name: Shell syntax\n'
                               '        run: |\n'
                               '          for script in initworkspace disassemble buildsource build patch '
                               'tools/docker_build.sh; do\n',
                               '          python3 tests/stage9_infrastructure.py\n'
                               '          python3 tests/community_updater.py\n'
                               '          python3 tests/community_signing.py\n'
                               '          python3 tests/community_webp.py\n'
                               '          python3 tests/community_native_packaging.py\n'
                               '      - name: Shell syntax\n'
                               '        run: |\n'
                               '          for script in initworkspace disassemble buildsource build patch '
                               'tools/docker_build.sh; do\n')],
 'RELEASING.md': [("which includes prereleases; do not direct CE users to the original project's downloads.\n"
  '\n'
  'This document describes maintainer gates, not permission to publish a release.\n'
  'The application remains `tv.twitch.bttvandroid.app`, version `0.44.1-beta`,\n'
  'versionCode `1208000340`, minSdk 29 and targetSdk 36. APK B version metadata is\n'
  'approved; this is not permission to sign or publish a release.\n'
  '\n'
  '## Reproducible inputs and isolated builds\n'
  '\n',
  "which includes prereleases; do not direct CE users to the original project's downloads.\n"
  '\n'
  'This document describes maintainer gates, not permission to publish a release.\n'
  'The application remains `tv.twitch.bttvandroid.app`, version `0.44.2-beta`,\n'
  'versionCode `1208000341`, minSdk 29 and targetSdk 36. This private candidate is\n'
  'approved for unsigned preparation only; signing, installation and publication\n'
  'require separate authorization.\n'
  '\n'
  '## Reproducible inputs and isolated builds\n'
  '\n'),
 ('1. `tools/build_production.py --unsigned` produces **unsigned.apk + unsigned.json**,\n'
  '   never a verified release. No signing inputs may enter that build process.\n'
  '2. `tools/sign_release.py` runs separately, preferably in an offline read-only\n'
  '   SDK container, after the build has exited. It aligns first with SDK 30.0.3\n'
  '   `zipalign -p 4`, signs with SDK `apksigner`, then runs the unchanged complete\n'
  '   `verify_release_apk.py` checks before exporting **twitch.apk + verification.json**.\n'
  '   Gradle, project shell scripts and application bytecode are not run there.\n'
  '\n',
  '1. `tools/build_production.py --unsigned` produces **unsigned.apk + unsigned.json**,\n'
  '   never a verified release. No signing inputs may enter that build process.\n'
  '2. `tools/sign_release.py` runs separately, preferably in an offline read-only\n'
  '   SDK container, after the build has exited. It aligns first with SDK 35.0.0\n'
  '   `zipalign -P 16 4`, signs with SDK 30.0.3 `apksigner`, then runs the complete\n'
  '   `verify_release_apk.py` checks before exporting **twitch.apk + verification.json**.\n'
  '   Gradle, project shell scripts and application bytecode are not run there.\n'
  '\n'),
 ('| `KSPASS_FILE` | Preferred: existing absolute external UTF-8 password file, without BOM, one '
  'nonempty line (optional LF/CRLF). Treat it as a secret and mount read-only. |\n'
  '| `KSPASS` | Compatibility alternative to the file, never both. SDK arguments contain only '
  '`env:KSPASS`, not its value. Avoid Docker environment secrets where file mounts suffice. |\n'
  '| `EXPECTED_SIGNER_SHA256` | Required 64 hex characters, without colons, for the approved '
  'certificate. Public debug identity is rejected. This fingerprint is public policy, not a '
  'private key. |\n'
  '| `ANDROID_SDK_ROOT` / `--sdk` | Existing SDK with Build Tools 30.0.3. No substitute toolchain '
  'or generated key is selected automatically. |\n'
  '\n'
  'The fixed key alias remains **bttv-android**, and store/key passwords must be the\n'
  'same. The signer first tries the store password for the key; stdin is closed, so\n',
  '| `KSPASS_FILE` | Preferred: existing absolute external UTF-8 password file, without BOM, one '
  'nonempty line (optional LF/CRLF). Treat it as a secret and mount read-only. |\n'
  '| `KSPASS` | Compatibility alternative to the file, never both. SDK arguments contain only '
  '`env:KSPASS`, not its value. Avoid Docker environment secrets where file mounts suffice. |\n'
  '| `EXPECTED_SIGNER_SHA256` | Required 64 hex characters, without colons, for the approved '
  'certificate. Public debug identity is rejected. This fingerprint is public policy, not a '
  'private key. |\n'
  '| `ANDROID_SDK_ROOT` / `--sdk` | Existing SDK with Build Tools 30.0.3 plus 35.0.0. Only '
  '`zipalign` comes from 35.0.0; Gradle, `aapt` and `apksigner` remain on 30.0.3. No fallback or '
  'generated key is selected automatically. |\n'
  '\n'
  'The fixed key alias remains **bttv-android**, and store/key passwords must be the\n'
  'same. The signer first tries the store password for the key; stdin is closed, so\n'),
 ('building instead of silently falling back or passing passwords in argv. Do not\n'
  'put signing settings in the repository `.env`. Keep secrets outside source,\n'
  'image build contexts, console commands, logs, test fixtures and artifacts.\n'
  '\n'
  'Android upgrades and the in-app updater require signing compatibility. The updater\n'
  'requires exact installed/downloaded certificate equality. A new private key cannot\n',
  'building instead of silently falling back or passing passwords in argv. Do not\n'
  'put signing settings in the repository `.env`. Keep secrets outside source,\n'
  'image build contexts, console commands, logs, test fixtures and artifacts.\n'
  '\n'
  'The Dockerfile installs the official Linux Build Tools 35.0.0 archive alongside\n'
  '30.0.3, pinned to SHA-256\n'
  '`BD3A4966912EB8B30ED0D00B0CDA6B6543B949D5FFE00BEA54C04C81E1561D88`.\n'
  'For a separately provisioned SDK, install the exact official `build-tools;35.0.0`\n'
  'package; do not replace 30.0.3 or substitute an arbitrary executable.\n'
  'The consumer APK includes only `arm64-v8a` and `armeabi-v7a`. Final verification\n'
  'rejects other ABI directories, compressed/misaligned native entries and invalid\n'
  'ELF load segments. Native ZIP offsets must be multiples of 16384; ARM64 ELF\n'
  'segments must support 16 KB pages, while ARMv7 retains 4 KB alignment. This also\n'
  'preserves 4 KB-device alignment. Alignment must happen BEFORE signing, never by\n'
  'editing an already signed APK. Historical 4 KB-aligned archives remain preserved\n'
  'but do not satisfy this stricter gate for newly prepared release candidates.\n'
  '\n'
  'Android upgrades and the in-app updater require signing compatibility. The updater\n'
  'requires exact installed/downloaded certificate equality. A new private key cannot\n'),
 ('header to an arbitrary URL. Keep the intended compatible release within this\n'
  "window; discovery does not promise to search the repository's entire history.\n"
  '\n'
  'Every candidate passes the same compatibility/asset metadata checks before an\n'
  'offer. The highest compatible, strictly newer **versionCode** in the window wins,\n'
  'regardless of tag ordering, publication order or prerelease status. Incompatible\n'
  'or malformed entries cannot become offers; conflicting highest-code assets fail\n'
  'closed. GitHub `prerelease: true` does not bypass package, SDK, dual-ARM, signer,\n'
  'SHA-256, size or version checks. Metadata checks never install an APK; downloading\n'
  'and installation require user confirmation. Downloads must originate at the\n'
  "configured repository's exact HTTPS release asset URL. Only the existing GitHub\n"
  'asset CDN hosts are accepted as redirects; arbitrary hosts/repositories are not.\n'
  '\n'
  'Before an end-to-end update test, choose the final public repository and install\n'
  'a baseline build containing this configuration. Existing upstream-only clients\n'
  'do not switch sources merely because a community release is published. Choose\n'
  'the repository before distributing that baseline: a later rename/redirect to a\n'
  'different repository is intentionally rejected by the allowlist.\n'
  '\n'
  'The baseline and candidate must have the same package and approved signing\n'
  'identity, and the candidate must have a strictly higher approved versionCode.\n'
  'No signing-key transition is authorized or implemented here. The metadata tool\n'
  'continues to reject the known public test/debug signing identity; a successful\n'
  'test-signed local build is not evidence of production signing readiness. Do not\n'
  'disable that gate to publish a release. Signing decisions and any migration from\n'
  'existing test installations require separate approval.\n'
  '\n'
  'After separately authorized build/upload/publication, verify both manual and\n'
  'automatic discovery against the real release, download/hash/signature checks,\n'
  'user-confirmed overlay installation and data preservation. Also test draft,\n'
  'wrong-signer/package, stale-code and cancelled-download rejection. No release\n'
  'workflow or publication is performed by the metadata tool.\n'
  '\n'
  'Before a future release, obtain explicit approval for a versionName/tag and a\n'
  'strictly increasing versionCode. The present name/tag already refers to an old\n'
  'upstream release and the current code must not be reused as a newer update. Do\n'
  'not infer approval for `0.44` or choose a new code automatically.\n'
  '\n'
  'After an approved APK has been uploaded to an authorized draft release, save the\n'
  'actual release API response as `release.json`. Only then is the final asset ID\n'
  'known. The local-only metadata tool independently re-verifies the actual APK:\n'
  '\n'
  '```bash\n'
  'python3 tools/release_metadata.py --help\n'
  '```\n'
  '\n'
  'Supply `--apk`, `--input`, `--expected-signer`, `--release-json`,\n'
  '`--previous-code` and a new `--output` path. The previous code is the highest\n'
  'supported installed code, not an invented smaller value. The tool emits one visible\n'
  '`bttv-update` fenced JSON block and performs no network or publishing action.\n'
  'It refuses test signing, reused codes, mismatched tag/version, ambiguous assets,\n'
  'incorrect size/hash and off-origin asset URLs. If GitHub does not provide an asset\n'
  'digest, independently confirm that the uploaded bytes match the verified local\n'
  'APK before publication. Preserve ordinary release notes\n'
  'outside that single block; the uploader must not substitute placeholder asset IDs.\n'
  '\n'
  'The block includes schemaVersion, standalone, packageName, versionName,\n'
  'versionCode, releaseTag, signerSha256, minSdk, supportedAbis, twitchVersion,\n'
  'assetId, assetName, sizeBytes and sha256. The existing app verifies the metadata\n'
  'and downloaded APK independently. Run the actual updater parser tests and review\n'
  'the final release JSON before an independently authorized publication. A candidate\n'
  'artifact or source merge is not proof that a future update installs successfully.\n'
  '\n'
  '## CE 0.44.x-beta test releases\n'
  '\n'
  'APK A is runtime-accepted by the user: privately signed `0.44.0-beta` /\n'
  '`1208000339` is installed and working on a Samsung Galaxy S25 Ultra. This is\n'
  'user-reported acceptance of A, not evidence that the A-to-B updater flow passed.\n'
  'APK B is approved for unsigned preparation: current source metadata is\n'
  '`0.44.1-beta` / `1208000340`.\n'
  '\n'
  '| Purpose | versionName | Matching future tag | versionCode |\n'
  '| --- | --- | --- | ---: |\n'
  '| A: accepted private-signed baseline | `0.44.0-beta` | `v0.44.0-beta` | `1208000339` |\n'
  '| B: approved unsigned update candidate | `0.44.1-beta` | `v0.44.1-beta` | `1208000340` |\n'
  '\n'
  'Use original BTTV-style patch numbering: `0.44.0-beta` -> `0.44.1-beta` ->\n'
  '`0.44.2-beta`, continuing as `0.44.x-beta`. This convention replaces the earlier\n'
  'beta-suffix proposal. Future metadata still requires approval; no third build is\n'
  'authorized by this sequence. Use decimal versionCode strings without leading zeros\n'
  "and increase the code for EVERY distributed beta/stable build. APK B's code is\n"
  "strictly greater than A's and below signed 32-bit limits. Tags must equal `v` +\n"
  'versionName. The updater orders by versionCode, not the text of a beta suffix.\n'
  '\n'
  'Preserve the SAME private certificate and package when signing B. A higher code\n'
  'and matching package allow an overlay only with signing compatibility and valid\n'
  'packaging. An unsigned artifact cannot prove that B has the same certificate,\n'
  'and no A-to-B installation success is claimed before the actual signed update.\n'
  'The existing verifier and updater certificate checks must remain strict.\n'
  '\n'
  'After separately approving private signing and publication:\n'
  '\n'
  '1. Keep the accepted A installation, signed APK, verification proof and unsigned\n'
  '   input unchanged. Build B to a new unsigned output and validate its metadata,\n'
  '   ZIP, DEX and complete dual-ARM native contents.\n'
  '2. Sign B with the SAME approved private identity as A using the existing isolated\n'
  "   alignment/signing/verifier stage. Check the signed B fingerprint equals A's;\n"
  "   verify B's actual hash, package, name and greater code. Never substitute test\n"
  '   signing or relax certificate pinning to force an update.\n'
  "3. Attach the actual uploaded signed asset's validated metadata block to a published\n"
  '   GitHub prerelease in `WhiteTree97/bttv-android-ce`, only after release approval.\n'
  '   `v0.44.1-beta` is a future tag; this preparation creates no tag or release.\n'
  '4. On the phone with A installed, test manual AND automatic discovery of B,\n'
  '   download/hash/package/certificate verification, explicit installation consent,\n'
  '   overlay installation and preservation of login/settings/data. Then verify B\n'
  '   offers neither A nor itself. Draft releases, wrong-signature/package assets,\n'
  '   corrupt downloads and untrusted URLs must continue to be rejected.\n'
  '\n'
  "The automatic check's persisted throttle/backoff remains in force; an immediate\n"
  'manual check is the appropriate first discovery test. Do not clear app data or\n'
  'weaken throttling/security checks to make an automatic prompt appear.\n'
  'APK B unsigned preparation does not authorize signing, installation, publication\n'
  'or tagging. The two-version updater test is still pending physical-device results.\n'
  '\n'
  '## Notices and remaining release gates\n'
  '\n',
  'header to an arbitrary URL. Keep the intended compatible release within this\n'
  "window; discovery does not promise to search the repository's entire history.\n"
  '\n'
  '### Normal manual GitHub releases\n'
  '\n'
  'After separately authorized building, signing and device testing:\n'
  '\n'
  '1. Increase versionName and versionCode, keeping the same package and certificate.\n'
  '2. Manually create a release in the configured CE repository. Its tag must be\n'
  '   exactly `v` + the APK versionName (for example `v0.44.3-beta`).\n'
  '3. Upload exactly one complete signed APK, then publish the release. Beta/\n'
  '   prerelease releases are supported. Normal release notes require no JSON.\n'
  '\n'
  'For a release without a `bttv-update` block, a newer semantic-version tag and\n'
  "GitHub's valid `sha256:` asset digest are mandatory. Missing digests, drafts,\n"
  'ambiguous APKs, invalid URLs and malformed compatibility blocks are excluded.\n'
  "The APK media type may be Android's APK type or generic octet-stream with an\n"
  '`.apk` filename. Tag ordering compares numeric components and prerelease\n'
  'identifiers, not strings; unknown/nonstandard installed version names fail closed.\n'
  'The tag is only a discovery hint: versionCode, SDK and ABI remain unknown until\n'
  'inspection and are never fabricated from the version name.\n'
  '\n'
  'Before an APK can become ready for installation, the app verifies its SHA-256,\n'
  'cryptographic signature, exact installed certificate, package, strictly greater\n'
  'real versionCode, tag/versionName equality, actual minSdk, ARM compatibility,\n'
  'standalone status and existing ZIP/native-library policies. The same checks run\n'
  'again after an explicit Install click. No download or installer is triggered by\n'
  'automatic discovery, and Android installation approval remains required.\n'
  'HTTPS origin/redirect restrictions, bounded transfers, cancellation and automatic\n'
  'check throttling are unchanged. Only configured-repository GitHub release asset\n'
  'URLs and the existing GitHub asset CDN redirect hosts are allowed.\n'
  '\n'
  'When two metadata-free candidates compete, the newer tag wins. Two legacy\n'
  'metadata candidates retain versionCode ordering; mixed candidates use version\n'
  'names because the bare candidate has no trusted versionCode yet. Conflicting\n'
  'same-version assets fail closed. Only the recent discovery window above is\n'
  "searched. A published release's missing server digest cannot be replaced by a\n"
  'hash typed into its normal notes.\n'
  '\n'
  '**Bootstrap:** installed 0.44.2-beta clients predate metadata-free discovery.\n'
  'They need one manual installation of a future build containing this change, or\n'
  'one update supplied through the existing compatibility-block mechanism. Changing\n'
  'a GitHub release alone cannot update the code already installed on a phone.\n'
  'A-to-B ADB/private installation testing does not prove full GitHub delivery.\n'
  '\n'
  '### Existing compatibility-block releases\n'
  '\n'
  'Existing valid `bttv-update` blocks remain supported with their stricter\n'
  'pre-download package, versionCode, signer, SDK, dual-ARM, size and hash checks.\n'
  'A broken or incompatible block never falls back to metadata-free discovery.\n'
  '`tools/release_metadata.py` remains available for maintaining those releases;\n'
  'it independently verifies the signed APK and generates a block from actual\n'
  'uploaded asset data. It does not upload or publish anything. This legacy path\n'
  'is optional for clients with the new discovery support; normal future manual\n'
  'uploads do not require a publishing script or release-description JSON.\n'
  '\n'
  'Both paths require a newer real versionCode and the same signing certificate at\n'
  'installation. No key transition, signing bypass or package migration is implied.\n'
  'Run updater JVM/Robolectric tests and then separately authorized physical-device\n'
  'manual/automatic discovery, digest failure, wrong signer/package, stale-code,\n'
  'SDK/ABI incompatibility, cancellation and explicit installation tests before\n'
  'claiming end-to-end update delivery. No release is created or changed by tests.\n'
  '\n'
  '## CE 0.44.x-beta test releases\n'
  '\n'
  'APK A is runtime-accepted by the user: privately signed `0.44.0-beta` /\n'
  '`1208000339` launched and worked on a Samsung Galaxy S25 Ultra.\n'
  'APK B is approved and runtime-accepted by the user: privately signed\n'
  '`0.44.1-beta` / `1208000340` installed over A with application data\n'
  'preserved. This is evidence of an overlay installation, not the full GitHub-based\n'
  'updater download/installation flow, which remains unverified.\n'
  '\n'
  'Current private candidate C is approved for unsigned preparation:\n'
  '`0.44.2-beta` / `1208000341`, including WebP 2.7 and dual-ARM 16 KB packaging.\n'
  '\n'
  '| Purpose | versionName | Existing/planned tag | versionCode |\n'
  '| --- | --- | --- | ---: |\n'
  '| A: accepted private-signed baseline | `0.44.0-beta` | `v0.44.0-beta` | `1208000339` |\n'
  '| B: accepted private-signed baseline | `0.44.1-beta` | `v0.44.1-beta` | `1208000340` |\n'
  '| C: private unsigned security candidate | `0.44.2-beta` | `v0.44.2-beta` | `1208000341` |\n'
  '\n'
  'Use original BTTV-style patch numbering: `0.44.0-beta` -> `0.44.1-beta` ->\n'
  '`0.44.2-beta`, continuing as `0.44.x-beta`. Decimal versionCode strings have no\n'
  'leading zeros and increase for every distributed beta/stable build. C is newer\n'
  'than both A and B and remains below signed 32-bit limits. Tags must equal `v` +\n'
  'versionName. The updater orders by versionCode, not the text of a beta suffix.\n'
  'Existing A/B tags and source-only releases remain immutable. The C tag in the\n'
  'table is a naming plan only; this task creates no tag or GitHub release.\n'
  '\n'
  'After separately authorizing private signing and device testing:\n'
  '\n'
  '1. Preserve the existing A/B signed APKs, proofs, archives and application data.\n'
  '   Use the new validated unsigned C artifact and a fresh signing output path.\n'
  '2. Sign C with the SAME private certificate and package as B using SDK35\n'
  '   `zipalign -P 16 4`, SDK30 apksigner and the complete independent verifier.\n'
  '   Verify the actual signed C certificate, SHA-256, package, version and greater\n'
  '   code. Never substitute test signing or relax certificate/URL checks.\n'
  '3. On a supported ARM device running B, test the separately authorized signed C\n'
  '   overlay and data retention, static/animated emotes, chat, playback and settings.\n'
  '   Check 4 KB ARM64, ARMv7 and 16 KB ARM64 behavior before compatibility claims.\n'
  '4. Test actual updater discovery/download/installation only after separate release\n'
  '   approval and proprietary distribution clearance. B should recognize C as newer;\n'
  '   C must offer neither A/B nor itself. Draft releases, corrupt downloads,\n'
  '   wrong-certificate/package assets and untrusted URLs must remain rejected.\n'
  '\n'
  "The automatic check's persisted throttle/backoff remains in force; use a manual\n"
  'check for the first discovery test. Do not clear application data or weaken\n'
  'security checks. Unsigned C preparation does not authorize signing, installation,\n'
  'tagging, publication or public redistribution. Final uploaded-asset IDs/hashes\n'
  'and the release metadata block can only be prepared after separately authorized\n'
  'signing/upload and complete verification; unsigned.json is not release metadata.\n'
  '\n'
  '## Notices and remaining release gates\n'
  '\n')]}

def before_webp_remediation(path, text):
    for old, new in _WEBP_EDITS.get(path, []):
        if not new or text.count(new) != 1:
            raise AssertionError('Unexpected WebP remediation block: ' + path)
        text = text.replace(new, old, 1)
    return text


if __name__ == '__main__':
    unittest.main()
