"""Portable community updater configuration/publisher and security contract tests."""
from pathlib import Path
import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import release_metadata as metadata


class CommunityUpdater(unittest.TestCase):
    def setUp(self):
        self.proof = dict(packageName='tv.twitch.bttvandroid.app', versionName='0.44.0-beta',
            versionCode=1208000339, testSigningIdentity=False, standalone=True, signerSha256='A'*64,
            minSdk=29, supportedAbis=['arm64-v8a','armeabi-v7a'], twitchVersion='31.2.0', sizeBytes=100, sha256='B'*64)
        self.release = dict(tag_name='v0.44.0-beta', draft=False, prerelease=True, assets=[dict(
            id=12, name='bttv.apk', state='uploaded', content_type='application/vnd.android.package-archive',
            size=100, browser_download_url='https://github.com/'+metadata.repository()+'/releases/download/v0.44.0-beta/bttv.apk', digest='sha256:'+'b'*64)])

    def test_single_repository_configuration(self):
        source=metadata.SOURCE.read_text()
        self.assertRegex(metadata.repository(),r'^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$')
        self.assertEqual(source.count('String REPOSITORY ='),1)
        for name in ['UpdateRelease','UpdateTransfer','Updater']:
            text=(metadata.SOURCE.parent/(name+'.java')).read_text()
            self.assertNotIn('bttv-android/bttv',text)
            self.assertNotIn(metadata.repository(),text)
        self.assertNotIn('bttv-android/bttv',Path(metadata.__file__).read_text())

    def test_publisher_uses_changed_repository_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'UpdateSource.java'
            configured=metadata.repository()
            path.write_text(metadata.SOURCE.read_text().replace(configured,'ExampleOwner/community'))
            with patch.object(metadata,'SOURCE',path):
                self.assertEqual(metadata.repository(),'ExampleOwner/community')
                self.release['assets'][0]['browser_download_url']=self.release['assets'][0]['browser_download_url'].replace(configured,'ExampleOwner/community')
                self.assertIn('```bttv-update',metadata.block(self.proof,self.release,1208000338))

    def test_malformed_or_ambiguous_configuration_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'UpdateSource.java'
            for value in ['https://evil.test','owner/repo/extra','owner/repo?x=1','owner/../repo','owner/repo#fragment']:
                path.write_text('    public static final String REPOSITORY = "'+value+'";\n')
                with patch.object(metadata,'SOURCE',path),self.subTest(value=value),self.assertRaises(ValueError):metadata.repository()
            path.write_text(metadata.SOURCE.read_text()*2)
            with patch.object(metadata,'SOURCE',path),self.assertRaises(ValueError):metadata.repository()

    def test_prerelease_and_draft_preparation_allowed(self):
        for draft in [False,True]:
            for prerelease in [False,True]:
                self.release.update(draft=draft,prerelease=prerelease)
                value=json.loads(metadata.block(self.proof,self.release,1208000338).split('\n',1)[1].rsplit('\n```',1)[0])
                self.assertEqual(value['versionCode'],1208000339)
                self.assertEqual(value['assetId'],12)

    def test_status_flags_must_be_actual_booleans(self):
        for key in ['draft','prerelease']:
            for value in [None,'true',1,0]:
                release=copy.deepcopy(self.release);release[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):metadata.block(self.proof,release,1208000338)

    def test_beta_keeps_identity_and_version_checks(self):
        for change in [dict(testSigningIdentity=True),dict(packageName='tv.twitch.android.app'),dict(versionCode=1208000338)]:
            with self.subTest(change=change),self.assertRaises(ValueError):metadata.block(dict(self.proof,**change),self.release,1208000338)

    def test_wrong_download_origins_and_encodings_rejected(self):
        good=self.release['assets'][0]['browser_download_url']
        for url in [good.replace(metadata.repository(),'bttv-android/bttv'),good+'?redirect=evil',good+'#x',
                    good.replace('github.com/','github.com.evil.test/'),good.replace('github.com/','user@github.com/'),
                    good.replace('https:','http:'),good.replace('/bttv.apk','/%62ttv.apk')]:
            release=copy.deepcopy(self.release);release['assets'][0]['browser_download_url']=url
            with self.subTest(url=url),self.assertRaises(ValueError):metadata.block(self.proof,release,1208000338)

    def test_controller_is_shared_and_verifier_is_unchanged(self):
        path=ROOT/'mod/app/src/main/java/bttv/updater'
        controller=(path/'UpdateController.java').read_text()
        self.assertEqual(controller.count('UpdateTransfer.discover('),1)
        self.assertIn('controller.checkAutomatically(', (path/'AutoUpdateChecker.java').read_text())
        for name in ['UpdateVerifier.java','AutoUpdateState.java','AutoUpdateChecker.java','UpdateSession.java']:
            baseline=subprocess.check_output(['git','show','7e40d52f76b74e0809836afd7ff8823317df436b:mod/app/src/main/java/bttv/updater/'+name],cwd=ROOT)
            if name=='AutoUpdateChecker.java':
                baseline=baseline.replace(b'text.setText("BTTV "+release.name', b'text.setText("BTTV Android CE "+release.name')
            self.assertEqual((path/name).read_bytes().replace(b'\r\n',b'\n'),baseline.replace(b'\r\n',b'\n'),name)

    def test_legacy_network_path_fails_closed(self):
        text=(metadata.SOURCE.parent/'Updater.java').read_text()
        self.assertNotIn('Network.get',text)
        self.assertNotIn('okhttp3',text)
        self.assertIn('listener.onError(new IOException("Legacy update callbacks are disabled.',text)
        self.assertIn('new UpdateDialog(activity, () -> { }).show()',text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
