"""Source boundaries complementing the real metadata-free updater JVM tests."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = '69d30b36a5f02e58ce43a8db918ef0c90731fcb6'
PREFIX = 'mod/app/src/main/java/bttv/updater/'


def read(name):
    return (ROOT/PREFIX/name).read_text()


def before(name):
    return subprocess.check_output(['git', 'show', BASE+':'+PREFIX+name], cwd=ROOT).decode().replace('\r\n', '\n')


def without_details(source):
    start = source.index('        if(state.release!=null) {')
    end = source.index('        result.setText(text);', start)
    return source[:start] + source[end:]


class ManualUploadSecurity(unittest.TestCase):
    def test_https_streaming_and_session_guards_unchanged(self):
        for name in ['UpdateTransfer.java', 'UpdateSource.java', 'UpdateSession.java',
                     'AutoUpdateChecker.java', 'Updater.java', 'UpdaterJobService.java']:
            self.assertEqual(read(name), before(name), name)

    def test_controller_adds_only_actual_inspected_details(self):
        self.assertEqual(read('UpdateController.java').replace('release=UpdateVerifier.verify(', 'UpdateVerifier.verify('),
                         before('UpdateController.java'))

    def test_installer_and_user_gestures_unchanged(self):
        self.assertEqual(without_details(read('UpdateDialog.java')), without_details(before('UpdateDialog.java')))
        self.assertIn('will be checked after download', read('UpdateDialog.java'))

    def test_native_zip_policy_not_relaxed(self):
        marker = '    static void nativeAndZip('
        self.assertEqual(read('UpdateVerifier.java').split(marker, 1)[1], before('UpdateVerifier.java').split(marker, 1)[1])

    def test_legacy_metadata_checks_preserved(self):
        source, old = read('UpdateRelease.java'), before('UpdateRelease.java')
        start, end = '            require((start==0', '            return new Inspection(candidate,"Compatible update available.'
        block = source[source.index(start):source.index(end)].replace('code,size,id,min,abis,true);', 'code,size,id,min,abis);')
        self.assertEqual(block, old[old.index(start):old.index(end)])

    def test_automatic_throttle_and_preferences_preserved(self):
        source = read('AutoUpdateState.java')
        source = source.replace('(pending.metadataProvided?pending.code>notified:pending.noticeKey()!=notified)', 'pending.code>notified')
        source = source.replace('notified=release.noticeKey();', 'notified=release.code;')
        self.assertEqual(source, before('AutoUpdateState.java'))

    def test_legacy_activity_cannot_trust_extras_or_install(self):
        source = read('UpdaterActivity.java')
        self.assertIn('new UpdateDialog(this,this::finish)', source)
        self.assertIn('dialog.dispose()', source)
        for unsafe in ['getIntent(', 'getStringExtra', 'startActivity(', 'OkHttp', 'INSTALL_PACKAGE', 'FileProvider']:
            self.assertNotIn(unsafe, source)

    def test_apk_crypto_identity_and_compatibility_gates_remain(self):
        source = read('UpdateVerifier.java')
        for gate in ['UpdateTransfer.digest(apk,cancel).equals(release.sha256)', 'signature.isVerified()',
                     'signature.getSignerCertificates().size()==1', 'signer.equals(installed.signer)',
                     'UpdateRelease.PACKAGE.equals(p.packageName)', 'p.getLongVersionCode()>installed.code',
                     'release.tag.equals("v"+p.versionName)', 'p.applicationInfo.minSdkVersion<=installed.sdk',
                     'p.splitNames.length==0', '!Collections.disjoint(installed.abis,abis)', 'nativeAndZip(apk,']:
            self.assertIn(gate, source)

    def test_no_active_publishing_scripts_or_apk_version_change(self):
        for name in ['publish_release.ps1', 'publish_release.py', 'CheckUpdateRelease.java']:
            self.assertFalse((ROOT/'tools'/name).exists())
        old = subprocess.check_output(['git', 'show', BASE+':bttv.manifest.json'], cwd=ROOT).decode()
        self.assertEqual((ROOT/'bttv.manifest.json').read_text(), old)


if __name__ == '__main__':
    unittest.main(verbosity=2)
