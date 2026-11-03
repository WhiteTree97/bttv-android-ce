"""Credential-free CE branding, attribution and release-security boundaries."""
from pathlib import Path
import json
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = 'e473bf2892f4498ca8472cd5751ed7aa9343ad99'
REPO = 'WhiteTree97/bttv-android-ce'
JAVA = 'mod/app/src/main/java/bttv/updater/'
STRINGS = 'mod/app/src/main/res/values/strings.xml'


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


def before(path):
    return subprocess.check_output(['git', 'show', BASE + ':' + path], cwd=ROOT)


class CommunityBranding(unittest.TestCase):
    def test_ce_release_and_badge_destinations(self):
        doc = read('README.md')
        self.assertIn('# BTTV Android CE', doc)
        self.assertIn('unofficial, independently community-maintained', doc)
        links = dict(re.findall(r'^\[([^]]+)\]: (\S+)$', doc, re.M))
        self.assertEqual(links['latest-release'], 'https://github.com/' + REPO + '/releases')
        for key in ['license-badge', 'bttv-version', 'downloads-latest', 'downloads-total']:
            self.assertIn('/' + REPO, links[key])
        self.assertIn('include_prereleases', links['bttv-version'])
        self.assertIn('/downloads-pre/', links['downloads-latest'])
        self.assertIn('build%20on-v31.2.0-blueviolet?style=flat-square', links['base-version'])
        self.assertEqual(links['upstream-project'], 'https://github.com/bttv-android/bttv')
        self.assertIn('original BTTV community', doc)

    def test_attribution_license_assets_and_history_preserved(self):
        paths = ['LICENSE', 'THIRD_PARTY_NOTICES.md', '.all-contributorsrc',
                 'mod/app/src/main/res/raw/bttv_third_party_notices.txt']
        tracked = subprocess.check_output(['git', 'ls-files', '.github'], cwd=ROOT).decode().splitlines()
        paths += [p for p in tracked if p.endswith(('.png', '.jpg', '.webp', '.svg'))]
        for path in paths:
            with self.subTest(path=path):
                if path.endswith(('.png', '.jpg', '.webp', '.svg')):
                    self.assertEqual((ROOT / path).read_bytes(), before(path))
                    continue
                self.assertEqual((ROOT / path).read_bytes().replace(b'\r\n', b'\n'), before(path).replace(b'\r\n', b'\n'))
        old = before('README.md').decode()
        current = read('README.md')
        self.assertEqual(old[old.index('## Contributors ✨'):], current[current.index('## Contributors ✨'):])
        self.assertIn('Made with ♥️ by [@FoseFx](https://github.com/FoseFx) and contributors. MIT License.', current)

    def test_user_support_routes_to_ce(self):
        for path in ['.github/ISSUE_TEMPLATE/bug_report.yaml',
                     '.github/ISSUE_TEMPLATE/Feature_request.md',
                     '.github/pull_request_template.md', 'CONTRIBUTING.md', 'architecture.md']:
            with self.subTest(path=path):
                source = read(path)
                self.assertIn('https://github.com/' + REPO + '/', source)
                self.assertNotIn('https://github.com/bttv-android/bttv/issues', source)
                self.assertNotIn('https://github.com/bttv-android/bttv/discussions/new', source)
                self.assertNotIn('/BTTV Android CE-ce/', source)

    def test_resource_identity_and_localizations_preserved(self):
        old = ET.fromstring(before(STRINGS))
        new = ET.fromstring(read(STRINGS))
        expected = {
            'app_name': 'BTTV Android CE',
            'login_landing_title': 'Welcome to\\nBTTV Android CE',
            'bttv_settings_entry_title': 'BTTV Android CE Settings',
            'bttv_auto_update_checks_enabled_secondary':
                'Check for new BTTV Android CE versions periodically and notify me when an update is available.',
        }
        self.assertEqual(len(old), len(new))
        for a, b in zip(old, new):
            self.assertEqual(a.attrib, b.attrib)
            if a.get('name') in expected:
                self.assertEqual(b.text, expected[a.get('name')])
            else:
                self.assertEqual(ET.tostring(a), ET.tostring(b))
        app = new.find("string[@name='app_name']")
        self.assertEqual(app.get('translatable'), 'false')
        for path in (ROOT / 'mod/app/src/main/res').glob('values-*/strings.xml'):
            rel = path.relative_to(ROOT).as_posix()
            self.assertEqual(path.read_bytes().replace(b'\r\n', b'\n'), before(rel).replace(b'\r\n', b'\n'), rel)
        self.assertIn('android:label="@string/app_name"', read('patches/AndroidManifest.xml.patch'))
        for path in ['buildsource', 'mod/app/src/main/java/bttv/Res.java']:
            self.assertEqual((ROOT / path).read_bytes().replace(b'\r\n', b'\n'), before(path).replace(b'\r\n', b'\n'))

    def test_display_changes_only_in_executable_sources(self):
        changes = {
            JAVA + 'AutoUpdateChecker.java': [('text.setText("BTTV "+release.name', 'text.setText("BTTV Android CE "+release.name')],
            JAVA + 'UpdateDialog.java': [('Installed BTTV ', 'Installed BTTV Android CE '),
                                         ('\\n\\nBTTV ', '\\n\\nBTTV Android CE '),
                                         ('allow BTTV to request', 'allow BTTV Android CE to request')],
            'build': [('android:text=\\"BTTV ${VERSION}\\"', 'android:text=\\"BTTV Android CE ${VERSION}\\"')],
            'mod/app/src/main/res/layout/bttv_stream_settings.xml':
                [('android:text="bttv-android"', 'android:text="@string/app_name"')],
        }
        for path, edits in changes.items():
            expected = before(path)
            for a, b in edits:
                self.assertIn(a.encode(), expected)
                expected = expected.replace(a.encode(), b.encode())
            self.assertEqual((ROOT / path).read_bytes(), expected, path)

    def test_updater_and_signing_security_sources_unchanged(self):
        paths = [JAVA + name + '.java' for name in ['UpdateSource', 'UpdateRelease', 'UpdateTransfer',
                 'UpdateVerifier', 'UpdateController', 'UpdateSession', 'AutoUpdateState', 'Updater']]
        # The signer's diagnostic wrapper is covered by community_signing's AST preservation test.
        paths += ['tools/build_production.py', 'tools/release_metadata.py',
                  'tools/verify_release_apk.py', 'tools/stage_production_input.py',
                  'patches/AndroidManifest.xml.patch', 'mod/app/build.gradle']
        paths += subprocess.check_output(['git', 'ls-files', '.github/workflows'], cwd=ROOT).decode().splitlines()
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual((ROOT / path).read_bytes().replace(b'\r\n', b'\n'), before(path).replace(b'\r\n', b'\n'))
        self.assertIn('REPOSITORY = "' + REPO + '"', read(JAVA + 'UpdateSource.java'))

    def test_approved_b_metadata_and_release_sequence(self):
        metadata = json.loads(read('bttv.manifest.json'))
        self.assertEqual(metadata['version'], '0.44.1-beta')
        self.assertEqual(metadata['versionCode'], '1208000340')
        doc = read('RELEASING.md')
        codes = [1208000339, int(metadata['versionCode']), 1208000341]
        self.assertTrue(all(a < b <= 2147483647 for a, b in zip(codes, codes[1:])))
        for version, code in [('0.44.0-beta', codes[0]), ('0.44.1-beta', codes[1])]:
            self.assertIn('`' + version + '` | `v' + version + '` | `' + str(code) + '`', doc)
        self.assertIn('APK A is runtime-accepted', doc)
        self.assertIn('APK B is approved', doc)
        self.assertIn('0.44.2-beta', doc)
        self.assertNotIn('0.44.0-beta.2', doc)
        self.assertIn('SAME private certificate and package', doc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
