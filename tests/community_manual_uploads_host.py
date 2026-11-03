"""Offline tests of metadata-free GitHub discovery and the real secure APK path.

SDK package metadata is shadowed by Robolectric; cryptographic checks use an
existing public signed fixture. No key, APK build, GitHub request or installer.
"""
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = runpy.run_path(str(ROOT/'tests/community_updater_host.py'))['SOURCES'].copy()
SOURCES['bttv/updater/UpdaterActivity.java'] = (ROOT/'mod/app/src/main/java/bttv/updater/UpdaterActivity.java').read_text()
auto = SOURCES['bttv/updater/AutoUpdateAndroidTest.java']
anchor = ' @Test public void sharedControllerAutomaticMetadataOnly()'
auto = auto.replace(anchor, r''' @Test public void bareManualUploadIsFoundByAutomaticControllerWithoutDownload()throws Exception {
  installedCeVersion("0.44.2-beta",1208000341L);
  body=new JSONArray().put(ManualUploadTest.release("0.44.3-beta")).toString();
  assertTrue(automatic()>0);done();assertEquals(UpdateRelease.Outcome.AVAILABLE,outcome);
  assertNotNull(found);assertEquals(0,found.code);assertFalse(found.metadataProvided);
  assertEquals(UpdateSession.State.AVAILABLE,controller.session.snapshot().state);
  assertFalse(new File(app.getCacheDir(),"bttv-updater").exists());
  assertNull(Shadows.shadowOf(app).getNextStartedActivity());
 }
''' + anchor, 1)
SOURCES['bttv/updater/AutoUpdateAndroidTest.java'] = auto
SOURCES['bttv/updater/ManualUploadTest.java'] = r'''package bttv.updater;
import org.junit.*;import static org.junit.Assert.*;import org.json.*;
import java.io.*;import java.util.*;
public class ManualUploadTest {
 static final byte[] BYTES={1,2,3};
 static UpdateRelease.Installed installed(){return new UpdateRelease.Installed("0.44.2-beta",1208000341L,UpdaterHostTest.CERT,30,UpdaterHostTest.ABIS);}
 static JSONObject release(String name)throws Exception {
  JSONObject c=UpdaterHostTest.compatibility(BYTES).put("versionName",name).put("releaseTag","v"+name);
  JSONObject r=UpdaterHostTest.release(c,BYTES).put("body","Normal human notes\n").put("prerelease",true);
  asset(r).put("digest","sha256:"+c.getString("sha256").toLowerCase(Locale.ROOT));return r;
 }
 static JSONObject asset(JSONObject r)throws Exception{return r.getJSONArray("assets").getJSONObject(0);}
 static UpdateRelease candidate(JSONObject r)throws Exception{return UpdateRelease.inspect(r.toString(),installed()).candidate;}
 @Test public void tagAndDigestAreOnlyProvisionalNotInventedApkMetadata()throws Exception {
  UpdateRelease r=candidate(release("0.44.3-beta"));assertNotNull(r);assertFalse(r.metadataProvided);
  assertEquals("0.44.3-beta",r.name);assertEquals(0,r.code);assertEquals(0,r.minSdk);assertTrue(r.abis.isEmpty());
  assertEquals(UpdaterHostTest.CERT,r.signer);assertEquals(64,r.sha256.length());
 }
 @Test public void mandatoryGithubDigestNeverFallsBackToNotes()throws Exception {
  for(Object digest:new Object[]{JSONObject.NULL,"","sha1:"+"A".repeat(40),"sha256:bad",true}) {
   JSONObject r=release("0.44.3-beta");asset(r).put("digest",digest);
   if(digest==JSONObject.NULL || "".equals(digest))assertNull(candidate(r));
   else UpdaterHostTest.rejects(()->candidate(r));
  }
  JSONObject r=release("0.44.3-beta");asset(r).remove("digest");assertNull(candidate(r));
 }
 @Test public void numericVersionAndPrereleaseOrderingNotLexical()throws Exception {
  for(String[] p:new String[][]{{"0.44.10-beta","0.44.9-beta"},{"0.45.0","0.45.0-beta"},
    {"0.45.0-beta.10","0.45.0-beta.2"},{"0.45.0-rc","0.45.0-beta"},{"1.0.0","0.99.99"}})
   assertTrue(UpdateRelease.compareVersions(p[0],p[1])>0);
  for(String s:new String[]{"0.44.2-beta","0.44.1-beta","0.43.99","0.44.2-alpha"})assertNull(candidate(release(s)));
  assertNotNull(candidate(release("0.44.2")));assertEquals(0,UpdateRelease.compareVersions("0.44.2-beta","0.44.2-beta"));
 }
 @Test public void unorderableVersionsFailClosed()throws Exception {
  for(String name:new String[]{"00.44.3","0.44.3-beta..1","0.44.3-beta.01","0.44.3-","v0.44.3","0.44.3+build"})
   UpdaterHostTest.rejects(()->candidate(release(name)));
  UpdaterHostTest.rejects(()->UpdateRelease.inspect(release("0.44.3").toString(),new UpdateRelease.Installed("snapshot",1,UpdaterHostTest.CERT,30,UpdaterHostTest.ABIS)));
 }
 @Test public void draftsAndMissingOrAmbiguousApksExcluded()throws Exception {
  assertNull(candidate(release("0.44.3-beta").put("draft",true)));
  JSONObject empty=release("0.44.3-beta").put("assets",new JSONArray());UpdaterHostTest.rejects(()->candidate(empty));
  JSONObject duplicate=release("0.44.3-beta");duplicate.getJSONArray("assets").put(new JSONObject(asset(duplicate).toString()).put("id",456));
  UpdaterHostTest.rejects(()->candidate(duplicate));
 }
 @Test public void browserOctetStreamApkStillRequiresAllOtherChecks()throws Exception {
  JSONObject r=release("0.44.3-beta");asset(r).put("content_type","application/octet-stream");assertNotNull(candidate(r));
  asset(r).put("digest",JSONObject.NULL);assertNull(candidate(r));
  asset(r).put("content_type","text/plain");UpdaterHostTest.rejects(()->candidate(r));
 }
 @Test public void malformedCompatibilityBlockCannotDowngradeToBareMode()throws Exception {
  for(String body:new String[]{"```bttv-update\n{}\n```","```bttv-update\r\n{}\r\n```","~~~bttv-update\n{}\n~~~","```BTTV-UPDATE\n{}\n```"})
   UpdaterHostTest.rejects(()->candidate(release("0.44.3-beta").put("body",body)));
 }
 @Test public void originAndStatusRestrictionsRemain()throws Exception {
  for(String url:new String[]{"http://github.com/x/a.apk",UpdateSource.downloadPrefix()+"v0.44.3-beta/bttv.apk?x=1",
    "https://github.com/other/repo/releases/download/v0.44.3-beta/bttv.apk"}) {
   JSONObject r=release("0.44.3-beta");asset(r).put("browser_download_url",url);UpdaterHostTest.rejects(()->candidate(r));
  }
  JSONObject r=release("0.44.3-beta");asset(r).put("state","starter");UpdaterHostTest.rejects(()->candidate(r));
 }
 @Test public void highestBareVersionAndMixedDiscoveryAreDeterministic()throws Exception {
  JSONArray list=new JSONArray().put(release("0.44.9-beta")).put(release("0.44.10-beta"));
  assertEquals("0.44.10-beta",UpdateRelease.select(list,installed()).candidate.name);
  JSONObject c=UpdaterHostTest.compatibility(BYTES).put("versionName","0.44.8-beta").put("releaseTag","v0.44.8-beta").put("versionCode",1208000342L);
  list.put(UpdaterHostTest.release(c,BYTES));assertEquals("0.44.10-beta",UpdateRelease.select(list,installed()).candidate.name);
  JSONObject conflict=release("0.44.10-beta");asset(conflict).put("id",124);list.put(conflict);
  UpdaterHostTest.rejects(()->UpdateRelease.select(list,installed()));
 }
 @Test public void mixedModesCannotProduceAnOrderDependentComparisonCycle()throws Exception {
  JSONObject highName=UpdaterHostTest.compatibility(BYTES).put("versionName","0.44.6-beta").put("releaseTag","v0.44.6-beta").put("versionCode",1208000342L);
  JSONObject highCode=UpdaterHostTest.compatibility(BYTES).put("versionName","0.44.4-beta").put("releaseTag","v0.44.4-beta").put("versionCode",1208000343L);
  JSONObject[] r={UpdaterHostTest.release(highName,BYTES),UpdaterHostTest.release(highCode,BYTES),release("0.44.5-beta")};
  for(int[] order:new int[][]{{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}}) {
   JSONArray list=new JSONArray();for(int i:order)list.put(r[i]);
   assertEquals("0.44.5-beta",UpdateRelease.select(list,installed()).candidate.name);
  }
 }
 @Test public void legacyBlockWithoutGithubDigestStillWorks()throws Exception {
  JSONObject c=UpdaterHostTest.compatibility(BYTES).put("versionName","0.44.3-beta").put("releaseTag","v0.44.3-beta").put("versionCode",1208000342L);
  UpdateRelease r=candidate(UpdaterHostTest.release(c,BYTES));assertTrue(r.metadataProvided);assertEquals(1208000342L,r.code);
 }
 @Test public void bareTransferStillVerifiesDigestAndNeverInstalls()throws Exception {
  File dir=java.nio.file.Files.createTempDirectory("bare-updater-").toFile();UpdateRelease r=candidate(release("0.44.3-beta"));
  try {
   File file=UpdateTransfer.download(r,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->new UpdaterHostTest.Connection(u,BYTES));assertTrue(file.delete());
   UpdaterHostTest.rejects(()->UpdateTransfer.download(r,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->new UpdaterHostTest.Connection(u,new byte[]{3,2,1})));
   assertEquals(0,dir.list().length);
  }finally{for(File f:dir.listFiles())f.delete();assertTrue(dir.delete());}
 }
 @Test public void automaticNoticesPersistWithoutFakeVersionCodes()throws Exception {
  AutoUpdateStateTest.Store store=new AutoUpdateStateTest.Store();AutoUpdateState state=new AutoUpdateState(store);
  UpdateRelease r=candidate(release("0.44.3-beta"));long now=1000000,t=state.begin(now);
  state.complete(t,now,UpdateRelease.Outcome.AVAILABLE,r,0);assertSame(r,state.notice());assertTrue(state.notified(r));assertEquals(-r.assetId,store.get(AutoUpdateState.NOTIFIED));
  state=new AutoUpdateState(store);t=state.begin(now+AutoUpdateState.DAY);state.complete(t,now+AutoUpdateState.DAY,UpdateRelease.Outcome.AVAILABLE,r,0);assertNull(state.notice());
  JSONObject next=release("0.44.4-beta");asset(next).put("id",125);state.disabled();t=state.begin(now+2*AutoUpdateState.DAY);
  UpdateRelease newer=candidate(next);state.complete(t,now+2*AutoUpdateState.DAY,UpdateRelease.Outcome.AVAILABLE,newer,0);assertSame(newer,state.notice());
 }
}'''

SOURCES['bttv/updater/ManualUploadAndroidTest.java'] = r'''package bttv.updater;
import org.junit.*;import static org.junit.Assert.*;import org.junit.runner.RunWith;
import org.robolectric.*;import org.robolectric.annotation.*;import org.robolectric.shadow.api.Shadow;
import org.robolectric.shadows.*;import org.robolectric.util.ReflectionHelpers;
import android.app.*;import android.content.*;import android.content.pm.*;import android.os.*;
import java.io.*;import java.nio.file.*;import java.util.*;import java.util.concurrent.*;import org.json.*;
@RunWith(RobolectricTestRunner.class) @Config(sdk=30,manifest=Config.NONE,packageName="tv.twitch.bttvandroid.app")
public class ManualUploadAndroidTest {
 UpdaterAndroidTest fixture;android.content.Context context;File original;
 @Before public void setup()throws Exception {
  fixture=new UpdaterAndroidTest();fixture.setup();context=fixture.context;original=fixture.original;
  PackageInfo p=context.getPackageManager().getPackageInfo(UpdateRelease.PACKAGE,PackageManager.GET_SIGNING_CERTIFICATES);
  p.versionName="0.43.1-beta";((ShadowPackageManager)Shadow.extract(context.getPackageManager())).installPackage(p);
 }
 JSONObject bare(File apk)throws Exception {
  JSONObject r=ManualUploadTest.release("0.43.2-beta");ManualUploadTest.asset(r).put("size",apk.length()).put("digest","sha256:"+UpdateTransfer.digest(apk,new UpdateTransfer.Cancel()));return r;
 }
 UpdateRelease candidate(File apk)throws Exception {return UpdateRelease.inspect(bare(apk).toString(),UpdateVerifier.installed(context)).candidate;}
 PackageInfo archive(){return context.getPackageManager().getPackageArchiveInfo(original.getAbsolutePath(),0);}
 void noInstaller(){assertNull(((ShadowApplication)Shadow.extract(RuntimeEnvironment.getApplication())).getNextStartedActivity());}
 @Test public void realSignedApkIsInspectedBeforeReady()throws Exception {
  UpdateRelease before=candidate(original);assertEquals(0,before.code);
  UpdateRelease verified=UpdateVerifier.verify(context,before,original,new UpdateTransfer.Cancel());
  assertEquals(1208000338L,verified.code);assertEquals(29,verified.minSdk);assertEquals(UpdaterHostTest.ABIS,verified.abis);assertFalse(verified.metadataProvided);noInstaller();
 }
 @Test public void actualPackageCodeNameSdkAndSplitGuardsReject()throws Exception {
  UpdateRelease r=candidate(original);PackageInfo p=archive();
  p.packageName="wrong.package";UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));p.packageName=UpdateRelease.PACKAGE;
  p.versionName="0.43.3-beta";UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));p.versionName="0.43.2-beta";
  p.setLongVersionCode(1208000337L);UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));p.setLongVersionCode(1208000338L);
  p.applicationInfo.minSdkVersion=31;UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));p.applicationInfo.minSdkVersion=29;
  p.splitNames=new String[]{"required"};UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));noInstaller();
 }
 @Test public void signerMismatchCannotBeOverriddenByGithubDigest()throws Exception {
  PackageInfo p=context.getPackageManager().getPackageInfo(UpdateRelease.PACKAGE,PackageManager.GET_SIGNING_CERTIFICATES);
  ((ShadowSigningInfo)Shadow.extract(p.signingInfo)).setSignatures(new Signature[]{new Signature(new byte[]{9,8,7})});
  ((ShadowPackageManager)Shadow.extract(context.getPackageManager())).installPackage(p);
  UpdateRelease r=candidate(original);UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));noInstaller();
 }
 @Test public void wrongDeviceAbiIsRejectedEvenAfterDiscovery()throws Exception {
  UpdateRelease r=candidate(original);ReflectionHelpers.setStaticField(Build.class,"SUPPORTED_ABIS",new String[]{"x86_64"});
  UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,original,new UpdateTransfer.Cancel()));noInstaller();
 }
 @Test public void tamperedSignatureRejectedEvenWhenAdvertisedHashMatchesTampering()throws Exception {
  File corrupt=File.createTempFile("bare-corrupt-",".apk");
  try {
   Files.copy(original.toPath(),corrupt.toPath(),StandardCopyOption.REPLACE_EXISTING);
   try(RandomAccessFile f=new RandomAccessFile(corrupt,"rw")){f.seek(500);int b=f.read();f.seek(500);f.write(b^1);}
   UpdateRelease r=candidate(corrupt);UpdaterHostTest.rejects(()->UpdateVerifier.verify(context,r,corrupt,new UpdateTransfer.Cancel()));noInstaller();
  }finally{assertTrue(corrupt.delete());}
 }
 @Test public void legacyActivityIgnoresArbitraryUrlAndCannotAutoInstall()throws Exception {
  ReflectionHelpers.setStaticField(UpdateController.class,"instance",null);
  Intent malicious=new Intent().putExtra("url","http://evil.invalid/unverified.apk").putExtra("body","untrusted");
  org.robolectric.android.controller.ActivityController<UpdaterActivity> activity=Robolectric.buildActivity(UpdaterActivity.class,malicious).setup();
  assertEquals(UpdateSession.State.IDLE,UpdateController.get(activity.get()).session.snapshot().state);noInstaller();activity.pause().stop().destroy();
 }
 @Test public void realControllerDownloadAndPreinstallReverificationAreMandatory()throws Exception {
  JSONObject listing=bare(original);byte[] json=new JSONArray().put(listing).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
  UpdateRelease r=UpdateRelease.inspect(listing.toString(),UpdateVerifier.installed(context)).candidate;
  File downloaded=new File(context.getCacheDir(),"bttv-updater/"+r.assetId+"-"+r.sha256+".apk");
  ((ShadowPackageManager)Shadow.extract(context.getPackageManager())).setPackageArchiveInfo(downloaded.getAbsolutePath(),archive());
  UpdateController controller=new UpdateController(context,url->{
   if(UpdateSource.metadataUrl(url.toString()))return new UpdaterHostTest.Connection(url,json);
   return new java.net.HttpURLConnection(url){public int getResponseCode(){return 200;}public long getContentLengthLong(){return original.length();}
    public InputStream getInputStream()throws IOException{return new FileInputStream(original);}public void connect(){}public void disconnect(){}public boolean usingProxy(){return false;}};
  });
  ThreadPoolExecutor worker=ReflectionHelpers.getField(controller,"worker");
  try {
   controller.check();worker.submit(()->{}).get(30,TimeUnit.SECONDS);assertEquals(UpdateSession.State.AVAILABLE,controller.session.snapshot().state);assertFalse(downloaded.exists());noInstaller();
   controller.download();worker.submit(()->{}).get(60,TimeUnit.SECONDS);assertEquals(UpdateSession.State.READY,controller.session.snapshot().state);assertEquals(1208000338L,controller.session.snapshot().release.code);noInstaller();
   try(RandomAccessFile f=new RandomAccessFile(downloaded,"rw")){f.seek(500);int b=f.read();f.seek(500);f.write(b^1);}
   assertTrue(controller.prepareInstall()>0);worker.submit(()->{}).get(30,TimeUnit.SECONDS);
   assertEquals(UpdateSession.State.ERROR,controller.session.snapshot().state);assertNull(controller.session.snapshot().file);assertFalse(downloaded.exists());noInstaller();
  }finally{worker.shutdownNow();if(downloaded.exists())downloaded.delete();}
 }
}'''

if __name__ == '__main__':
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    for name, source in SOURCES.items():
        p = out/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(source, encoding='utf-8')
