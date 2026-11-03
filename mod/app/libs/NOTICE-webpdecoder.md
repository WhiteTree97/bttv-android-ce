# GlideWebpDecoder provenance and compatibility

Runtime artifact: `com.github.zjupure:webpdecoder:2.7.4.16.0`, supplied unmodified
by [Maven Central](https://repo.maven.apache.org/maven2/com/github/zjupure/webpdecoder/2.7.4.16.0/).
Pinned upstream revision: `56d3f2523d546bd069600b8ee2435a0e0e2c3c07`
([release 2.7](https://github.com/zjupure/GlideWebpDecoder/releases/tag/2.7)).
Exact artifact, POM, source, native-library and inspection-input hashes are in
[webpdecoder-inputs.json](../../../../tools/webpdecoder-inputs.json).

The wrapper retains Apache-2.0 terms, Copyright 2017-2018 zjupure. libwebp retains
Google's BSD-style terms and patent grant. Full license texts are preserved in
`res/raw/bttv_third_party_notices.txt` and `res/raw/bttv_apksig_license.txt`.
The libwebp 1.3.2 COPYING/PATENTS texts match the previously bundled texts.
No library-source modifications or reproducible native compilation are claimed.

## Why this dependency does not upgrade Glide

The artifact POM requests Glide 4.16.0. BTTV excludes that transitive dependency
and explicitly constrains Glide to 4.12.0, including its existing gifdecoder.
This is a locally verified compatibility combination, not a vendor-published
`2.7.4.12.0` artifact: no such artifact exists in the inspected Maven metadata.
All 80 external Glide/GIF member references in the decoder resolve against
4.12.0. The original decoder's class/member signatures used by BTTV remain
available, including component registration, WebpDrawable start/stop/callback,
and the frame decoder/provider interfaces. Java sources introduce no Kotlin
runtime. Tests inspect the actual class files rather than relying on the
artifact's version suffix. Physical-device animation testing remains required.

## Native security and page sizes

The replaced `2.0.4.12.0` AAR (SHA-256
`EED26A7819E2F20AC4305851B3B789D5E14CC01F6659A66B52D73B273A873740`)
contains ARM64/ARMv7 binaries reporting **1.2.0**. Its older provider source
comment saying 1.1.0 was not an accurate statement of the shipped binary.

The replacement's ARM64 and ARMv7 `WebPGetDecoderVersion` implementations return
`0x010302` (1.3.2). The pinned source contains the segmented Huffman-table fix;
upstream [2.4](https://github.com/zjupure/GlideWebpDecoder/releases/tag/2.4)
introduced libwebp 1.3.2 for CVE-2023-4863, retained in 2.6 and 2.7.
This establishes remediation of that vulnerability in the bundled decoder,
not an assertion that every system/Twitch decoder is current or vulnerability-free.

2.7's ARM64 and x86_64 PT_LOAD segments are 16 KB aligned. ARMv7 remains ELF32
ARM with 4 KB segment alignment, as appropriate for the retained 32-bit ABI.
JNI dependencies remain Android system libraries; no libc++_shared.so is needed.
The new AAR omits the obsolete decoder-only `armeabi` ABI. The consumer APK
filters to ARM64 and ARMv7: source-AAR x86/x86_64 binaries remain recorded for
provenance but are not packaged, because Twitch's input has no full x86 runtime.
Production alignment uses the separately pinned SDK 35.0.0 `zipalign -P 16 4`
before SDK 30.0.3 signing. Final verification independently requires 16 KB native
ZIP offsets and 16 KB ARM64 ELF load alignment (4 KB for ARMv7). Device testing
is still required; structural alignment alone is not runtime certification.

## Reproducing the artifact inspection

Run `python3 tests/community_webp.py` for offline policy/parser regressions.
Supply the official AAR and Glide/GIF 4.12.0 JARs to:

```sh
python3 tools/verify_webp_decoder.py --aar webpdecoder-2.7.4.16.0.aar \
  --glide glide-4.12.0.jar --gif gifdecoder-4.12.0.jar
```

Optional `--previous` accepts the old decoder's classes.jar for API comparison;
`--apk` verifies that a newly built APK contains the exact replacement natives.
This is dependency inspection, not a replacement for protected release signing
or the existing APK verifier.
