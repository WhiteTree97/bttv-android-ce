"""Offline JVM fixtures for community release discovery; reuses the existing verifier/lifecycle suite."""
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = runpy.run_path(str(ROOT / 'tests/stage7_auto_updater_host.py'))['SOURCES'].copy()
SOURCES['bttv/updater/Updater.java'] = (ROOT / 'mod/app/src/main/java/bttv/updater/Updater.java').read_text()
SOURCES['bttv/Res.java'] = (ROOT / 'mod/app/src/main/java/bttv/Res.java').read_text()
SOURCES['bttv/Data.java'] = 'package bttv; public final class Data {}'
SOURCES['bttv/ResUtil.java'] = 'package bttv; public final class ResUtil { public static String getLocaleString(android.content.Context c,Res.strings key){return key.name();} }'
SOURCES['androidx/annotation/NonNull.java'] = 'package androidx.annotation; public @interface NonNull {}'
SOURCES['bttv/updater/UpdaterActivity.java'] = 'package bttv.updater; public class UpdaterActivity extends android.app.Activity {}'
SOURCES['tv/twitch/android/feature/viewer/main/navigation/PersistentBannerPresenter.java'] = r'''package tv.twitch.android.feature.viewer.main.navigation;
public class PersistentBannerPresenter {
 public interface PersistentBannerPresenterListener {void installBannerShown();void installUpdate();void updateDismissed();}
 public void setListener(PersistentBannerPresenterListener listener){}
 public void setShouldShowUpdateBanner(boolean show){}
}'''
SOURCES['bttv/updater/LegacyUpdateBoundaryTest.java'] = r'''package bttv.updater;
import org.junit.*;import static org.junit.Assert.*;import org.junit.runner.RunWith;
import org.robolectric.*;import org.robolectric.annotation.Config;
@RunWith(RobolectricTestRunner.class) @Config(sdk=30,manifest=Config.NONE)
public class LegacyUpdateBoundaryTest {
 @Test public void legacyCallbackNeverOffersUnverifiedAsset(){
  for(boolean manual:new boolean[]{true,false}){
   final int[] errors={0};
   Updater.checkForUpdates(RuntimeEnvironment.getApplication(),new Updater.UpdateCallbackListener(){
    public void onNoUpdate(){fail("legacy callback pretended to check");}
    public void onUpdate(String version,String body,String url,String html){fail("unverified legacy offer");}
    public void onError(Throwable failure){assertTrue(failure instanceof java.io.IOException);errors[0]++;}
   },manual);
   assertEquals(1,errors[0]);
  }
 }
}'''
SOURCES['bttv/updater/CommunityReleaseTest.java'] = r'''package bttv.updater;
import org.junit.*;import static org.junit.Assert.*;import org.json.*;
import java.io.*;import java.net.*;import java.util.*;
public class CommunityReleaseTest {
 final byte[] bytes={1,2,3};
 JSONObject release(long code,boolean beta)throws Exception {
  JSONObject c=UpdaterHostTest.compatibility(bytes).put("versionCode",code);
  return UpdaterHostTest.release(c,bytes).put("prerelease",beta);
 }
 UpdateRelease.Inspection select(JSONObject... releases)throws Exception {
  JSONArray a=new JSONArray();for(JSONObject r:releases)a.put(r);
  return UpdateRelease.select(a,UpdaterHostTest.installed());
 }
 JSONObject ceMetadata(String name,long code,byte[] bytes,String signer)throws Exception {
  return UpdaterHostTest.compatibility(bytes).put("versionName",name).put("releaseTag","v"+name)
   .put("versionCode",code).put("signerSha256",signer);
 }
 @Test public void approvedCeAtoBDiscoveryAndIdentityChecks()throws Exception {
  byte[] bytes={1,2,3};String signer="C".repeat(64); // Synthetic public-certificate fixture, never a real key.
  UpdateRelease.Installed first=new UpdateRelease.Installed("0.44.0-beta",1208000339L,signer,30,UpdaterHostTest.ABIS);
  UpdateRelease.Installed updated=new UpdateRelease.Installed("0.44.1-beta",1208000340L,signer,30,UpdaterHostTest.ABIS);
  JSONObject a=UpdaterHostTest.release(ceMetadata("0.44.0-beta",1208000339L,bytes,signer),bytes).put("prerelease",true);
  JSONObject metadata=ceMetadata("0.44.1-beta",1208000340L,bytes,signer);
  JSONObject b=UpdaterHostTest.release(metadata,bytes).put("prerelease",true);
  String listing=new JSONArray().put(a).put(b).toString();
  UpdateRelease found=UpdateTransfer.discover(first,new UpdateTransfer.Cancel(),u->connection(u,listing)).candidate;
  assertNotNull(found);assertEquals("0.44.1-beta",found.name);assertEquals("v0.44.1-beta",found.tag);assertEquals(1208000340L,found.code);
  assertNull(UpdateTransfer.discover(updated,new UpdateTransfer.Cancel(),u->connection(u,listing)).candidate);
  assertNull(UpdateRelease.select(new JSONArray().put(a),updated).candidate);
  assertNull(UpdateRelease.select(new JSONArray().put(b),updated).candidate);
  b.put("draft",true);assertNull(UpdateRelease.select(new JSONArray().put(a).put(b),first).candidate);
  JSONObject wrongSigner=new JSONObject(metadata.toString()).put("signerSha256","D".repeat(64));
  UpdaterHostTest.rejects(()->UpdateRelease.inspect(UpdaterHostTest.release(wrongSigner,bytes).put("prerelease",true).toString(),first));
  JSONObject wrongPackage=new JSONObject(metadata.toString()).put("packageName","tv.twitch.android.app");
  UpdaterHostTest.rejects(()->UpdateRelease.inspect(UpdaterHostTest.release(wrongPackage,bytes).put("prerelease",true).toString(),first));
 }
 @Test public void approvedCeBDownloadStillRequiresExactSha256()throws Exception {
  byte[] bytes={1,2,3};String signer="C".repeat(64);
  UpdateRelease.Installed first=new UpdateRelease.Installed("0.44.0-beta",1208000339L,signer,30,UpdaterHostTest.ABIS);
  JSONObject b=UpdaterHostTest.release(ceMetadata("0.44.1-beta",1208000340L,bytes,signer),bytes).put("prerelease",true);
  UpdateRelease candidate=UpdateRelease.inspect(b.toString(),first).candidate;
  File dir=java.nio.file.Files.createTempDirectory("ce-b-download-fixture-").toFile();
  try {
   File file=UpdateTransfer.download(candidate,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->new UpdaterHostTest.Connection(u,bytes));
   assertArrayEquals(bytes,java.nio.file.Files.readAllBytes(file.toPath()));assertTrue(file.delete());
   byte[] corrupt={3,2,1};
   UpdaterHostTest.rejects(()->UpdateTransfer.download(candidate,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->new UpdaterHostTest.Connection(u,corrupt)));
   assertEquals(0,dir.list().length);
  } finally {for(File file:dir.listFiles())file.delete();assertTrue(dir.delete());}
 }
 @Test public void approvedCeBtoCDiscoveryAndIdentityChecks()throws Exception {
  byte[] bytes={1,2,3};String signer="C".repeat(64); // Synthetic public-certificate fixture, never a real key.
  UpdateRelease.Installed first=new UpdateRelease.Installed("0.44.1-beta",1208000340L,signer,30,UpdaterHostTest.ABIS);
  UpdateRelease.Installed updated=new UpdateRelease.Installed("0.44.2-beta",1208000341L,signer,30,UpdaterHostTest.ABIS);
  JSONObject a=UpdaterHostTest.release(ceMetadata("0.44.1-beta",1208000340L,bytes,signer),bytes).put("prerelease",true);
  JSONObject metadata=ceMetadata("0.44.2-beta",1208000341L,bytes,signer);
  JSONObject b=UpdaterHostTest.release(metadata,bytes).put("prerelease",true);
  String listing=new JSONArray().put(a).put(b).toString();
  UpdateRelease found=UpdateTransfer.discover(first,new UpdateTransfer.Cancel(),u->connection(u,listing)).candidate;
  assertNotNull(found);assertEquals("0.44.2-beta",found.name);assertEquals("v0.44.2-beta",found.tag);assertEquals(1208000341L,found.code);
  assertNull(UpdateTransfer.discover(updated,new UpdateTransfer.Cancel(),u->connection(u,listing)).candidate);
  assertNull(UpdateRelease.select(new JSONArray().put(a),updated).candidate);
  assertNull(UpdateRelease.select(new JSONArray().put(b),updated).candidate);
  b.put("draft",true);assertNull(UpdateRelease.select(new JSONArray().put(a).put(b),first).candidate);
  JSONObject wrongSigner=new JSONObject(metadata.toString()).put("signerSha256","D".repeat(64));
  UpdaterHostTest.rejects(()->UpdateRelease.inspect(UpdaterHostTest.release(wrongSigner,bytes).put("prerelease",true).toString(),first));
  JSONObject wrongPackage=new JSONObject(metadata.toString()).put("packageName","tv.twitch.android.app");
  UpdaterHostTest.rejects(()->UpdateRelease.inspect(UpdaterHostTest.release(wrongPackage,bytes).put("prerelease",true).toString(),first));
 }
 @Test public void approvedCeCDownloadStillRequiresExactSha256()throws Exception {
  byte[] bytes={1,2,3};String signer="C".repeat(64);
  UpdateRelease.Installed first=new UpdateRelease.Installed("0.44.1-beta",1208000340L,signer,30,UpdaterHostTest.ABIS);
  JSONObject b=UpdaterHostTest.release(ceMetadata("0.44.2-beta",1208000341L,bytes,signer),bytes).put("prerelease",true);
  UpdateRelease candidate=UpdateRelease.inspect(b.toString(),first).candidate;
  File dir=java.nio.file.Files.createTempDirectory("ce-c-download-fixture-").toFile();
  try {
   File file=UpdateTransfer.download(candidate,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->new UpdaterHostTest.Connection(u,bytes));
   assertArrayEquals(bytes,java.nio.file.Files.readAllBytes(file.toPath()));assertTrue(file.delete());
   byte[] corrupt={3,2,1};
   UpdaterHostTest.rejects(()->UpdateTransfer.download(candidate,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->new UpdaterHostTest.Connection(u,corrupt)));
   assertEquals(0,dir.list().length);
  } finally {for(File file:dir.listFiles())file.delete();assertTrue(dir.delete());}
 }
 @Test public void highestCompatibleCodeNotApiOrder()throws Exception {
  assertEquals(1208000341L,select(release(1208000339L,false),release(1208000341L,true),release(1208000340L,false)).candidate.code);
  assertEquals(1208000341L,select(release(1208000341L,false),release(1208000339L,true)).candidate.code);
 }
 @Test public void draftsNeverOffered()throws Exception {
  JSONObject draft=release(1208000342L,true).put("draft",true);
  assertNull(select(draft).candidate);assertEquals(1208000339L,select(draft,release(1208000339L,true)).candidate.code);
 }
 @Test public void prereleaseCannotBypassSigner()throws Exception {
  JSONObject c=UpdaterHostTest.compatibility(bytes).put("versionCode",1208000342L).put("signerSha256",UpdaterHostTest.OFFICIAL);
  assertEquals(1208000339L,select(UpdaterHostTest.release(c,bytes).put("prerelease",true),release(1208000339L,false)).candidate.code);
 }
 @Test public void invalidHighCandidateDoesNotHideValidCandidate()throws Exception {
  JSONObject bad=release(1208000342L,true);bad.put("body","missing compatibility");
  assertEquals(1208000339L,select(bad,release(1208000339L,false)).candidate.code);
  bad.put("body","```bttv-update\n{}\n```");assertEquals(1208000339L,select(bad,release(1208000339L,true)).candidate.code);
 }
 @Test public void conflictingHighestCodeFailsClosed()throws Exception {
  JSONObject a=release(1208000341L,true),b=release(1208000341L,false);
  b.getJSONArray("assets").getJSONObject(0).put("digest","sha256:"+"A".repeat(64));
  // Conflicting metadata is invalid before selection; two independently valid conflicting tags must also be rejected.
  assertNotNull(select(a,b).candidate);
  JSONObject c=UpdaterHostTest.compatibility(bytes).put("versionCode",1208000341L).put("versionName","0.45.0-beta").put("releaseTag","v0.45.0-beta");
  UpdaterHostTest.rejects(()->select(a,UpdaterHostTest.release(c,bytes)));
 }
 @Test public void sameAndOlderCodesNeverOffer()throws Exception {
  assertNull(select(release(1208000338L,true),release(1208000337L,false)).candidate);
 }
 @Test public void lowerCodeConflictDoesNotHideHigherValidRelease()throws Exception {
  JSONObject lower=UpdaterHostTest.compatibility(bytes).put("versionCode",1208000339L).put("versionName","0.45.0-beta").put("releaseTag","v0.45.0-beta");
  assertEquals(1208000340L,select(release(1208000339L,true),UpdaterHostTest.release(lower,bytes),release(1208000340L,false)).candidate.code);
  assertEquals(1208000340L,select(release(1208000340L,false),release(1208000339L,true),UpdaterHostTest.release(lower,bytes)).candidate.code);
 }
 @Test public void emptyAndMalformedListsFailSafely()throws Exception {
  assertEquals(UpdateRelease.Outcome.NOT_NEWER,select().outcome);
  UpdaterHostTest.rejects(()->UpdateRelease.select(new JSONArray().put(JSONObject.NULL),UpdaterHostTest.installed()));
  for(String text:new String[]{"{}","null","[","[".repeat(33)+"]".repeat(33)})
   UpdaterHostTest.rejects(()->UpdateTransfer.discover(UpdaterHostTest.installed(),new UpdateTransfer.Cancel(),u->connection(u,text)));
 }
 UpdaterHostTest.Connection connection(URL u,String text){return new UpdaterHostTest.Connection(u,text.getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 @Test public void paginationIsBoundedAndSelectsAcrossPages()throws Exception {
  List<String> urls=new ArrayList<>();JSONArray full=new JSONArray();for(int i=0;i<UpdateSource.PER_PAGE;i++)full.put(release(1208000339L,false));
  UpdateRelease.Inspection found=UpdateTransfer.discover(UpdaterHostTest.installed(),new UpdateTransfer.Cancel(),u->{
   urls.add(u.toString());try{return connection(u,urls.size()==1?full.toString():new JSONArray().put(release(1208000341L,true)).toString());}catch(Exception e){throw new IOException(e);}
  });
  assertEquals(1208000341L,found.candidate.code);assertEquals(Arrays.asList(UpdateSource.releasesPage(1),UpdateSource.releasesPage(2)),urls);
 }
 @Test public void fullPagesNeverCauseUnboundedCrawl()throws Exception {
  int[] calls={0};JSONArray full=new JSONArray();for(int i=0;i<UpdateSource.PER_PAGE;i++)full.put(release(1208000339L,true));
  assertNotNull(UpdateTransfer.discover(UpdaterHostTest.installed(),new UpdateTransfer.Cancel(),u->{calls[0]++;return connection(u,full.toString());}).candidate);
  assertEquals(UpdateSource.MAX_PAGES,calls[0]);
 }
 @Test public void nextPageFailureNeverOffersPartialResult()throws Exception {
  int[] calls={0};JSONArray full=new JSONArray();for(int i=0;i<UpdateSource.PER_PAGE;i++)full.put(release(1208000339L,false));
  UpdaterHostTest.rejects(()->UpdateTransfer.discover(UpdaterHostTest.installed(),new UpdateTransfer.Cancel(),u->{
   if(++calls[0]>1)throw new IOException("fixture");return connection(u,full.toString());
  }));assertEquals(2,calls[0]);
 }
 @Test public void oversizedPageAndResponseRejected()throws Exception {
  JSONArray full=new JSONArray();for(int i=0;i<=UpdateSource.PER_PAGE;i++)full.put(release(1208000339L,false));
  UpdaterHostTest.rejects(()->UpdateTransfer.discover(UpdaterHostTest.installed(),new UpdateTransfer.Cancel(),u->connection(u,full.toString())));
  UpdaterHostTest.rejects(()->UpdateTransfer.discover(UpdaterHostTest.installed(),new UpdateTransfer.Cancel(),u->connection(u," ".repeat(UpdateRelease.MAX_METADATA+1))));
 }
 @Test public void cancellationStopsBetweenPages()throws Exception {
  UpdateTransfer.Cancel token=new UpdateTransfer.Cancel();int[] calls={0};
  UpdaterHostTest.rejects(()->UpdateTransfer.discover(UpdaterHostTest.installed(),token,u->{calls[0]++;token.cancel();return connection(u,"[]");}));assertEquals(1,calls[0]);
 }
 @Test public void urlTrustRejectsUpstreamAndLookalikes()throws Exception {
  String good=UpdateSource.downloadPrefix()+"v0.44.0-beta/bttv.apk";
  assertTrue(UpdateRelease.assetUrl(good,"v0.44.0-beta","bttv.apk"));assertTrue(UpdateTransfer.allowed(good,false));
  for(String url:new String[]{good+"?x=1",good+"#fragment",good.replace("github.com/","github.com:443/"),
    good.replace("https:","http:"),good.replace("github.com/","github.com.evil.test/"),good.replace("github.com/","user@github.com/"),
    "https://github.com/bttv-android/bttv/releases/download/v0.44.0-beta/bttv.apk",good.replace("/bttv.apk","/%2e%2e/bttv.apk"),
    good.replace("/bttv.apk","/../bttv.apk"),good.replace("/bttv.apk","/other/bttv.apk")}){
   assertFalse(url,UpdateRelease.assetUrl(url,"v0.44.0-beta","bttv.apk"));assertFalse(url,UpdateTransfer.allowed(url,false));
  }
  for(String url:new String[]{UpdateRelease.API+"&extra=1",UpdateRelease.API.replace("page=1","page=4"),
    "https://api.github.com/repos/bttv-android/bttv/releases/latest","https://evil.test/releases"})assertFalse(UpdateTransfer.allowed(url,true));
 }
 @Test public void legitimateCdnRedirectRetainsHashVerification()throws Exception {
  UpdateRelease r=UpdaterHostTest.candidate(bytes);File dir=java.nio.file.Files.createTempDirectory("community-update").toFile();int[] calls={0};
  try {
   File f=UpdateTransfer.download(r,dir,new UpdateTransfer.Cancel(),(n,t)->{},u->{
    UpdaterHostTest.Connection c=connection(u,"");if(++calls[0]==1){c.status=302;c.location="https://release-assets.githubusercontent.com/github-production-release-asset/test?signature=fixture";return c;}
    return new UpdaterHostTest.Connection(u,bytes);
   });assertEquals(2,calls[0]);assertEquals(r.sha256,UpdateTransfer.digest(f,new UpdateTransfer.Cancel()));
  }finally{for(File f:dir.listFiles())assertTrue(f.delete());assertTrue(dir.delete());}
 }
 @Test public void redirectToOtherRepositoryNeverOpensDestination()throws Exception {
  int[] calls={0};String good=UpdateSource.downloadPrefix()+"v0.44.0-beta/bttv.apk";
  UpdaterHostTest.rejects(()->UpdateTransfer.open(good,false,new UpdateTransfer.Cancel(),u->{
   calls[0]++;UpdaterHostTest.Connection c=connection(u,"");c.status=302;c.location="https://github.com/other/repo/releases/download/v1.0.0/a.apk";return c;
  }));assertEquals(1,calls[0]);
 }
 @Test public void malformedStatusFlagsRejectedEvenForBeta()throws Exception {
  for(Object flag:new Object[]{"true",1,JSONObject.NULL}){
   final JSONObject draft=release(1208000339L,true).put("draft",flag);UpdaterHostTest.rejects(()->select(draft));
   final JSONObject bad=release(1208000339L,true).put("prerelease",flag);UpdaterHostTest.rejects(()->select(bad));
  }
 }
}
'''

if __name__ == '__main__':
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=False)
    for name, source in SOURCES.items():
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding='utf-8')
