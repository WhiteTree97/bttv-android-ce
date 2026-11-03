package bttv.updater;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Conservative configured-release contract. Unknown compatibility is never an install offer. */
public final class UpdateRelease {
    enum Outcome { AVAILABLE, NOT_NEWER, UNSUPPORTED, MISSING_ASSET, INVALID_METADATA,
        NETWORK, RATE_LIMIT, SERVER, HTTP_ERROR, CANCELLED, DISABLED, INTERNAL_ERROR }
    static final class Problem extends IOException {
        final Outcome outcome;
        Problem(String message) { this(message,Outcome.INVALID_METADATA); }
        Problem(String message,Outcome outcome) { super(message); this.outcome=outcome; }
    }
    public static final String PACKAGE = "tv.twitch.bttvandroid.app";
    public static final String API = UpdateSource.releasesPage(1);
    public static final String MIME = "application/vnd.android.package-archive";
    public static final int MAX_METADATA = 262144, MAX_NOTES = 24576;
    public static final long MAX_APK = 536870912L;
    private static final String MARKER = "```bttv-update\n";

    public static final class Installed {
        public final String name, signer;
        public final long code;
        public final int sdk;
        public final List<String> abis;
        public Installed(String name, long code, String signer, int sdk, List<String> abis) {
            this.name = name; this.code = code; this.signer = signer;
            this.sdk = sdk; this.abis = Collections.unmodifiableList(new ArrayList<>(abis));
        }
    }

    public static final class Inspection {
        public final UpdateRelease candidate;
        public final String message;
        final Outcome outcome;
        Inspection(UpdateRelease candidate, String message, Outcome outcome) {
            this.candidate = candidate; this.message = message; this.outcome=outcome;
        }
    }

    public final String tag, name, notes, url, assetName, sha256, signer, twitchVersion;
    public final long code, size, assetId;
    public final int minSdk;
    public final List<String> abis;
    public final boolean metadataProvided;

    private UpdateRelease(String tag, String name, String notes, String url, String assetName,
                          String sha256, String signer, String twitchVersion, long code,
                          long size, long assetId, int minSdk, List<String> abis, boolean metadataProvided) {
        this.tag=tag; this.name=name; this.notes=notes; this.url=url; this.assetName=assetName;
        this.sha256=sha256; this.signer=signer; this.twitchVersion=twitchVersion;
        this.code=code; this.size=size; this.assetId=assetId; this.minSdk=minSdk;
        this.abis=Collections.unmodifiableList(new ArrayList<>(abis));
        this.metadataProvided=metadataProvided;
    }

    UpdateRelease inspected(long actualCode,int actualMin,List<String> actualAbis) {
        return new UpdateRelease(tag,name,notes,url,assetName,sha256,signer,twitchVersion,
                actualCode,size,assetId,actualMin,actualAbis,metadataProvided);
    }

    // Unknown versionCode is never invented. Negative asset IDs occupy a separate
    // namespace in the existing automatic-notice preference until APK inspection.
    long noticeKey() { return metadataProvided?code:-assetId; }

    public static Inspection inspect(String text, Installed installed) throws IOException {
        try {
            boundedJson(text);
            JSONObject json = new JSONObject(text);
            String tag = string(json, "tag_name", 100);
            String releaseName=json.isNull("name")?tag:json.optString("name",tag);
            require(releaseName.length()<=200,"Release name is too large");
            require(tag.matches("v[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.-]+)?"), "Invalid release tag");
            require(json.get("draft") instanceof Boolean && json.get("prerelease") instanceof Boolean,
                    "Missing release status");
            if (json.getBoolean("draft"))
                return new Inspection(null, "No compatible update: draft releases are excluded.",Outcome.UNSUPPORTED);
            String notes = json.isNull("body") ? "" : json.optString("body", "");
            require(notes.length() <= MAX_NOTES, "Release notes are too large");
            JSONArray assets = json.getJSONArray("assets");
            require(assets.length() <= 64, "Too many release assets");
            int start=notes.indexOf(MARKER);
            JSONObject apk = null;
            for (int i=0; i<assets.length(); i++) {
                JSONObject item=assets.getJSONObject(i);
                if (!MIME.equals(item.optString("content_type"))) {
                    if(start>=0 || !item.optString("name").toLowerCase(java.util.Locale.ROOT).endsWith(".apk"))continue;
                    require("application/octet-stream".equals(item.optString("content_type")), "Unexpected APK media type");
                }
                require(apk==null, "Ambiguous APK assets");
                require("uploaded".equals(item.optString("state")), "APK is not uploaded");
                apk=item;
            }
            if(apk==null)throw new Problem("No uploaded APK asset",Outcome.MISSING_ASSET);
            String assetName=string(apk,"name",180);
            require(assetName.matches("[A-Za-z0-9][A-Za-z0-9._-]*\\.apk"), "Invalid APK asset name");
            long id=number(apk,"id",Long.MAX_VALUE), size=number(apk,"size",MAX_APK);
            String url=string(apk,"browser_download_url",1024);
            require(assetUrl(url,tag,assetName), "Unexpected APK origin");
            String digest=apk.isNull("digest") ? "" : apk.optString("digest", "");
            if (!digest.isEmpty()) require(digest.matches("sha256:[0-9a-fA-F]{64}"), "Invalid asset digest");

            // Explicit, visible release-note metadata; no hidden test mode or arbitrary sidecar URL.
            if (start<0) {
                require(!notes.matches("(?is).*(```|~~~)[ \\t]*bttv-update.*"), "Malformed compatibility metadata");
                if (digest.isEmpty()) return new Inspection(null,
                        "No update offered: GitHub does not provide an APK SHA-256 digest.",Outcome.UNSUPPORTED);
                if (compareVersions(tag.substring(1),installed.name)<=0) return new Inspection(null,
                        "No update: the release tag is not newer than this installation.",Outcome.NOT_NEWER);
                compatible(!Collections.disjoint(installed.abis,java.util.Arrays.asList("arm64-v8a","armeabi-v7a")),
                        "Device ABI is unsupported");
                UpdateRelease candidate=new UpdateRelease(tag,tag.substring(1),notes,url,assetName,
                        hash(digest.substring(7)),hash(installed.signer),"",0,size,id,0,
                        Collections.emptyList(),false);
                return new Inspection(candidate,
                        "Newer release found. APK compatibility will be verified after download.",Outcome.AVAILABLE);
            }
            require((start==0 || notes.charAt(start-1)=='\n') && notes.indexOf(MARKER,start+1)<0,
                    "Ambiguous compatibility metadata");
            int end=notes.indexOf("\n```",start+MARKER.length());
            require(end>=0, "Incomplete compatibility metadata");
            String compatibility=notes.substring(start+MARKER.length(),end);
            boundedJson(compatibility);
            JSONObject c=new JSONObject(compatibility);
            compatible(number(c,"schemaVersion",1)==1 && c.getBoolean("standalone"), "Unsupported compatibility schema");
            compatible(PACKAGE.equals(string(c,"packageName",100)), "Wrong package");
            String name=string(c,"versionName",96);
            require(tag.equals("v"+name) && tag.equals(string(c,"releaseTag",100)), "Version/tag mismatch");
            long code=number(c,"versionCode",Integer.MAX_VALUE);
            if (code<=installed.code) return new Inspection(null, "No compatible update: the release is not newer than this installation.",Outcome.NOT_NEWER);
            String signer=hash(string(c,"signerSha256",64));
            compatible(signer.equals(hash(installed.signer)), "The release signing identity is incompatible with this installation");
            int min=(int)number(c,"minSdk",1000);
            compatible(min<=installed.sdk, "Android version is unsupported");
            String twitch=string(c,"twitchVersion",32);
            compatible(twitch.matches("31\\.[0-9]+\\.[0-9]+"), "Unsupported Twitch base");
            JSONArray abiJson=c.getJSONArray("supportedAbis");
            compatible(abiJson.length()==2, "A complete dual-ARM release is required");
            List<String> abis=new ArrayList<>();
            for(int i=0;i<abiJson.length();i++) {
                String abi=abiJson.getString(i);
                require((abi.equals("arm64-v8a") || abi.equals("armeabi-v7a")) && !abis.contains(abi), "Invalid ABI metadata");
                abis.add(abi);
            }
            compatible(!Collections.disjoint(abis,installed.abis), "Device ABI is unsupported");
            require(id==number(c,"assetId",Long.MAX_VALUE) && assetName.equals(string(c,"assetName",180))
                    && size==number(c,"sizeBytes",MAX_APK), "Asset metadata mismatch");
            String sha=hash(string(c,"sha256",64));
            require(digest.isEmpty() || digest.substring(7).equalsIgnoreCase(sha), "Conflicting APK hashes");
            String display=notes.substring(0,start)+notes.substring(end+4);
            UpdateRelease candidate=new UpdateRelease(tag,name,display.trim(),url,assetName,sha,signer,twitch,
                    code,size,id,min,abis,true);
            return new Inspection(candidate,"Compatible update available.",Outcome.AVAILABLE);
        } catch (IOException e) { throw e; }
        catch (Exception e) { throw new Problem("Invalid release metadata"); }
    }

    /** Do not trust API order, version-name ordering, or prerelease status as proof of compatibility. */
    static Inspection select(JSONArray releases, Installed installed) throws IOException {
        require(releases.length() <= UpdateSource.PER_PAGE * UpdateSource.MAX_PAGES, "Too many releases");
        Inspection best = null, bareBest = null, fallback = null;
        IOException invalid = null;
        boolean conflicting = false, bareConflicting = false;
        for (int i = 0; i < releases.length(); i++) {
            Inspection result;
            try {
                Object item = releases.get(i);
                require(item instanceof JSONObject, "Invalid release entry");
                result = inspect(item.toString(), installed);
            } catch (Exception e) {
                if (invalid == null) invalid = e instanceof IOException ? (IOException)e : new Problem("Invalid release entry");
                continue;
            }
            if (result.candidate == null) {
                if (fallback == null || result.outcome == Outcome.NOT_NEWER) fallback = result;
            } else if (!result.candidate.metadataProvided) {
                int order=bareBest==null?1:compareVersions(result.candidate.name,bareBest.candidate.name);
                if(order>0) { bareBest=result; bareConflicting=false; }
                else if(order==0)bareConflicting|=!sameAsset(result.candidate,bareBest.candidate);
            } else if (best == null || result.candidate.code>best.candidate.code) {
                best = result;
                conflicting = false;
            } else if (result.candidate.code==best.candidate.code) {
                conflicting|=!sameAsset(result.candidate,best.candidate);
            }
        }
        // Select within each trust mode first. A pairwise mix of code ordering
        // and tag ordering would otherwise be non-transitive and API-order-dependent.
        if(bareBest!=null) {
            int order=best==null?1:compareVersions(bareBest.candidate.name,best.candidate.name);
            if(order>0) { best=bareBest; conflicting=bareConflicting; }
            else if(order==0)conflicting|=bareConflicting || !sameAsset(best.candidate,bareBest.candidate);
        }
        require(!conflicting, "Conflicting releases identify the same version");
        if (best != null) return best;
        if (fallback != null) return fallback;
        if (invalid != null) throw invalid;
        return new Inspection(null, "No compatible update in the recent published releases.", Outcome.NOT_NEWER);
    }

    private static boolean sameAsset(UpdateRelease a,UpdateRelease b) {
        return a.url.equals(b.url) && a.sha256.equals(b.sha256) && a.assetId==b.assetId && a.size==b.size;
    }

    static int compareVersions(String a,String b) throws IOException {
        String[] left=version(a), right=version(b);
        for(int i=0;i<3;i++) { int c=numeric(left[i],right[i]); if(c!=0)return c; }
        if(left[3]==null || right[3]==null)return left[3]==right[3]?0:left[3]==null?1:-1;
        String[] x=left[3].split("\\."), y=right[3].split("\\.");
        for(int i=0;i<Math.min(x.length,y.length);i++) {
            boolean xn=x[i].matches("[0-9]+"), yn=y[i].matches("[0-9]+");
            int c=xn && yn?numeric(x[i],y[i]):xn!=yn?(xn?-1:1):x[i].compareTo(y[i]);
            if(c!=0)return c;
        }
        return Integer.compare(x.length,y.length);
    }

    private static String[] version(String name) throws IOException {
        compatible(name!=null && name.length()<=96 && name.matches(
                "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?"),
                "Cannot safely compare this version name");
        int dash=name.indexOf('-');
        String core=dash<0?name:name.substring(0,dash), pre=dash<0?null:name.substring(dash+1);
        if(pre!=null)for(String part:pre.split("\\."))compatible(!part.matches("0[0-9]+"),"Invalid numeric prerelease");
        String[] p=core.split("\\.");return new String[]{p[0],p[1],p[2],pre};
    }

    private static int numeric(String a,String b) {
        return a.length()==b.length()?a.compareTo(b):Integer.compare(a.length(),b.length());
    }

    static void boundedJson(String text) throws IOException {
        require(text!=null && !text.trim().isEmpty() && text.length()<=MAX_METADATA, "Empty or oversized metadata");
        int depth=0; boolean quoted=false, escaped=false;
        for(int i=0;i<text.length();i++) {
            char c=text.charAt(i);
            if(quoted) { if(escaped) escaped=false; else if(c=='\\') escaped=true; else if(c=='"') quoted=false; }
            else if(c=='"') quoted=true;
            else if(c=='{' || c=='[') require(++depth<=32,"Metadata nesting is too deep");
            else if(c=='}' || c==']') require(--depth>=0,"Invalid metadata nesting");
        }
        require(depth==0 && !quoted,"Incomplete metadata");
    }

    static String string(JSONObject j,String key,int max) throws Exception {
        Object o=j.get(key);
        require(o instanceof String,"Invalid "+key);
        String s=(String)o;
        require(!s.isEmpty() && s.length()<=max && !s.matches("(?s).*[\\x00-\\x1f\\x7f].*"),"Invalid "+key);
        return s;
    }
    static long number(JSONObject j,String key,long max) throws Exception {
        Object o=j.get(key);
        require(o instanceof Integer || o instanceof Long,"Invalid "+key);
        long v=((Number)o).longValue(); require(v>0 && v<=max,"Invalid "+key); return v;
    }
    static String hash(String s) throws IOException {
        require(s!=null && s.matches("[0-9a-fA-F]{64}"),"Missing or invalid SHA-256 identity");
        return s.toUpperCase(java.util.Locale.ROOT);
    }
    static boolean assetUrl(String value,String tag,String file) {
        try {
            URI u=new URI(value);
            return "https".equals(u.getScheme()) && "github.com".equals(u.getHost()) && u.getPort()==-1
                    && u.getUserInfo()==null && u.getQuery()==null && u.getFragment()==null
                    && value.equals(UpdateSource.downloadPrefix()+tag+"/"+file);
        } catch(Exception e) { return false; }
    }
    static void require(boolean ok,String reason) throws IOException { if(!ok) throw new Problem(reason); }
    private static void compatible(boolean ok,String reason) throws IOException {
        if(!ok)throw new Problem(reason,Outcome.UNSUPPORTED);
    }
}
