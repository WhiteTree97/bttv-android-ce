"""Run the existing Twitch 31 build in a NEW isolated workspace and output folder."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from prepare_twitch_input import inspect
from stage_production_input import ROOT, stage

# Explicit pending infrastructure inputs allow validation before committing.
# No glob includes untracked source or diagnostic files.
INFRA_INPUTS = (
    "THIRD_PARTY_NOTICES.md",
    "mod/app/src/main/res/raw/bttv_third_party_notices.txt",
    "tools/build_production.py", "tools/docker_build.sh",
    "tools/prepare_twitch_input.py", "tools/twitch-31.2.0-inputs.json",
    "tools/verify_release_apk.py", "tools/release_metadata.py",
    "tools/apk_native_policy.py",
    "tools/webpdecoder-inputs.json",
    "tests/stage9_infrastructure.py", "RELEASING.md",
)


def build(source, workspace, output, unsigned=False):
    if any(os.environ.get(key) for key in ('KS', 'KSPASS', 'KSPASS_FILE', 'KEYSTORE', 'KEYSTORE_BASE64')):
        raise ValueError('Signing credentials must not enter the build stage; prepare --unsigned, then use sign_release.py separately')
    source, workspace, output = source.resolve(), workspace.resolve(), output.resolve()
    if workspace.exists() or output.exists():
        raise ValueError("Workspace and output must both be NEW; no caches/artifacts are overwritten")
    if workspace == output or workspace in output.parents or output in workspace.parents:
        raise ValueError("Workspace and output must be separate directories")
    inspect(source)
    stage(ROOT, workspace, additional=INFRA_INPUTS)
    shutil.copyfile(source, workspace / "twitch.zip")
    # CRLF in a Windows checkout must not reach Linux shebangs or Bash syntax.
    for relative in ["initworkspace", "disassemble", "buildsource", "patch", "build", "mod/gradlew", "tools/docker_build.sh"]:
        path = workspace / relative
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
        path.chmod(0o755)
    (workspace / "dist").mkdir()
    env = dict(os.environ, DOCKER="true", BTTV_UNSIGNED_BUILD='1' if unsigned else '')
    # This identity is for generated, disposable disassembly commits only.
    env.update(GIT_AUTHOR_NAME="BTTV build", GIT_AUTHOR_EMAIL="build@localhost",
               GIT_COMMITTER_NAME="BTTV build", GIT_COMMITTER_EMAIL="build@localhost")
    output.mkdir(parents=True)
    with (output / "build.log").open("wb") as log:
        subprocess.run(["bash", "initworkspace"], cwd=workspace, env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    apk = workspace / "dist/twitch.apk"
    if not apk.is_file() or apk.stat().st_size == 0:
        raise ValueError("Build did not export dist/twitch.apk")
    if unsigned:
        # Not a release artifact: only the separate signer may export verified twitch.apk.
        from verify_release_apk import sha256
        with apk.open('rb') as src, (output / 'unsigned.apk').open('xb') as dst:
            shutil.copyfileobj(src, dst)
        proof = dict(unsigned=True, sha256=sha256(output / 'unsigned.apk'),
                     sizeBytes=(output / 'unsigned.apk').stat().st_size, inputSha256=sha256(source))
        with (output / 'unsigned.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(proof, indent=2) + '\n')
        print('Unsigned intermediate only; not a verified release:', output / 'unsigned.apk', proof['sha256'])
        return
    # Validate the completed file before exporting, never watch a partial APK.
    command = [os.sys.executable, str(workspace / "tools/verify_release_apk.py"),
               str(apk), "--input", str(source), "--output", str(output / "verification.json")]
    command.append("--allow-test-key")
    if os.environ.get("EXPECTED_SIGNER_SHA256"):
        command.extend(["--expected-signer", os.environ["EXPECTED_SIGNER_SHA256"]])
    subprocess.run(command, env=env, check=True)
    with apk.open("rb") as src, (output / "twitch.apk").open("xb") as dst:
        shutil.copyfileobj(src, dst)
    from verify_release_apk import sha256
    proof = json.loads((output / "verification.json").read_text())
    if sha256(output / "twitch.apk") != proof["sha256"]:
        raise ValueError("Export hash mismatch")
    print("Validated APK:", output / "twitch.apk", proof["sha256"], flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--workspace", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument('--unsigned', action='store_true', help='Prepare only an unverified intermediate for the separate protected signing stage')
    args = p.parse_args()
    build(args.input, args.workspace, args.output, args.unsigned)
