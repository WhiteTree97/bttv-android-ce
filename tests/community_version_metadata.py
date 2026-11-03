"""APK A versions, final injection boundary and unchanged release trust inputs."""
import json
from pathlib import Path
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = '631ecb684e13f0eb5b51bd38e514160ceb8a6352'


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


def original(path):
    return subprocess.check_output(['git', 'show', BASE + ':' + path], cwd=ROOT).decode().replace('\r\n', '\n')


class ApkAVersion(unittest.TestCase):
    def test_approved_metadata_and_decimal_code(self):
        config = json.loads(read('bttv.manifest.json'))
        self.assertEqual(config, {'version': '0.44.0-beta', 'versionCode': '1208000339'})
        self.assertRegex(config['versionCode'], r'^[1-9][0-9]*$')
        old = json.loads(original('bttv.manifest.json'))
        self.assertLess(int(old['versionCode']), int(config['versionCode']))
        self.assertLess(int(config['versionCode']), 1208000340)
        self.assertLessEqual(int(config['versionCode']), 2147483647)

    def test_existing_manifest_injection_and_legacy_footer_rule(self):
        script = read('build')
        self.assertEqual(script, original('build'))
        for source in ['VERSION=$(jq -r ".version" bttv.manifest.json)',
                       'VERSIONCODE=$(jq -r ".versionCode" bttv.manifest.json)',
                       'android:versionCode=\\"${VERSIONCODE}\\"',
                       'android:versionName=\\"${VERSION}\\"',
                       'android:text=\\"BTTV Android CE ${VERSION}\\"']:
            self.assertIn(source, script)
        # The footer substitution is inherited and conditional on a BTTV literal;
        # do not invent a footer when Twitch's native layout uses runtime binding.
        self.assertLess(script.index('# Set version'), script.index(' b . --use-aapt2'))
        self.assertLess(script.index('BTTV_UNSIGNED_BUILD'), script.index('$JAVA_PATH -jar $UBER_APK_SIGNER_PATH -a'))

    def test_library_and_build_shell_versions_are_not_app_versions(self):
        for path in ['mod/app/build.gradle', 'mod/consumer/build.gradle', 'mod/twitch/build.gradle']:
            self.assertEqual(read(path), original(path), path)
            self.assertIn('versionName "1.0"', read(path))
            self.assertIn('versionCode 1', read(path))
        verifier = read('mod/app/src/main/java/bttv/updater/UpdateVerifier.java')
        self.assertIn('getPackageInfo(', verifier)
        self.assertNotIn('BuildConfig.VERSION', verifier)

    def test_twitch_inputs_package_and_security_unchanged(self):
        # Signing diagnostics have a separate AST-level unchanged-policy contract.
        paths = ['tools/twitch-31.2.0-inputs.json', 'patches/AndroidManifest.xml.patch',
                 'tools/build_production.py', 'tools/verify_release_apk.py',
                 'tools/release_metadata.py', 'tools/stage_production_input.py',
                 'mod/app/src/main/java/bttv/updater/UpdateSource.java',
                 'mod/app/src/main/java/bttv/updater/UpdateRelease.java',
                 'mod/app/src/main/java/bttv/updater/UpdateTransfer.java',
                 'mod/app/src/main/java/bttv/updater/UpdateVerifier.java']
        for path in paths:
            self.assertEqual(read(path), original(path), path)
        pin = json.loads(read(paths[0]))
        self.assertEqual(pin['versionName'], '31.2.0')
        self.assertIn('tv.twitch.bttvandroid.app', read(paths[1]))
        self.assertIn('WhiteTree97/bttv-android-ce', read('mod/app/src/main/java/bttv/updater/UpdateSource.java'))

    def test_existing_ce_label_and_resources_unchanged(self):
        path = 'mod/app/src/main/res/values/strings.xml'
        self.assertEqual(read(path), original(path))
        resources = ET.fromstring(read(path))
        self.assertEqual(resources.find("string[@name='app_name']").text, 'BTTV Android CE')
        self.assertEqual(resources.find("string[@name='app_name']").get('translatable'), 'false')
        self.assertIn('android:label="@string/app_name"', read('patches/AndroidManifest.xml.patch'))
        self.assertEqual(read('LICENSE'), original('LICENSE'))
        self.assertEqual(read('THIRD_PARTY_NOTICES.md'), original('THIRD_PARTY_NOTICES.md'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
