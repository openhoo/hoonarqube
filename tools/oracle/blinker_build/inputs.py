"""Prepare verified public inputs outside the offline container."""

import hashlib
import json
import platform
import subprocess
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "inputs.json").read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def git(root, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", root, *args], timeout=120
    )


def source(work, mirror):
    root = work / "git"
    root.mkdir()
    git(root, "init", "-q")
    git(
        root,
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=1",
        "--update-shallow",
        mirror,
        MANIFEST["commit"],
    )
    rev = git(root, "rev-parse", "FETCH_HEAD").decode().strip()
    require(
        rev == MANIFEST["commit"]
        and git(root, "rev-parse", rev + "^{tree}").decode().strip()
        == MANIFEST["tree"],
        "different Git commit or tree",
    )
    git(root, "update-ref", "HEAD", rev)
    export = work / "source"
    export.mkdir()
    inventory = {}
    for item in git(root, "ls-tree", "-rz", rev).split(b"\0"):
        if not item:
            continue
        meta, name = item.decode().split("\t")
        mode, kind, oid = meta.split()
        require(
            kind == "blob"
            and mode in {"100644", "100755"}
            and name in MANIFEST["files_sha256"]
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts,
            "unexpected source entry",
        )
        blob = git(root, "cat-file", "blob", oid)
        inventory[name] = digest(blob)
        path = export / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(blob)
        path.chmod(int(mode[-3:], 8))
    require(inventory == MANIFEST["files_sha256"], "source inventory differs")
    return (
        export,
        root / ".git",
        git(root, "show", "-s", "--format=%ct", rev).decode().strip(),
    )


def platform_for_host():
    return {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}[
        platform.machine()
    ]


def wheels(work, architecture, cache=None):
    arch = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
    dest = work / "wheels"
    dest.mkdir()
    selected = {
        name: info
        for name, info in MANIFEST["wheels"].items()
        if name.endswith(("-none-any.whl", arch + ".whl"))
    }
    require(len(selected) == 7, "unexpected wheel selection")
    for name, info in selected.items():
        require(
            Path(name).name == name
            and info["url"].startswith("https://files.pythonhosted.org/"),
            "invalid wheel input",
        )
        if cache is None:
            with urllib.request.urlopen(info["url"], timeout=45) as r:
                data = r.read(8 * 1024 * 1024 + 1)
        else:
            data = (cache / name).read_bytes()
        require(digest(data) == info["sha256"], "wheel digest mismatch: " + name)
        (dest / name).write_bytes(data)
    return dest


def test_wheel(src, dependencies, epoch, architecture):
    script = HERE / "wheel_test.py"
    image = MANIFEST["image"]
    cmd = [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/" + architecture,
        "--network",
        "none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "65534:65534",
        "--cpus",
        "2",
        "--memory",
        "768m",
        "--memory-swap",
        "768m",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--tmpfs",
        "/job:rw,nosuid,nodev,exec,size=256m,mode=1777",
        "-e",
        "SOURCE_DATE_EPOCH=" + epoch,
    ]
    for local, remote in (
        (src, "/input"),
        (dependencies, "/wheels"),
        (script, "/proof.py"),
    ):
        cmd += ["-v", str(local) + ":" + remote + ":ro"]
    proc = subprocess.run(
        [*cmd, image, "python", "/proof.py"],
        check=False,
        capture_output=True,
        timeout=290,
    )
    require(
        proc.returncode == 0,
        "isolated build/tests failed: " + proc.stderr.decode(errors="replace")[-2000:],
    )
    res = json.loads(proc.stdout)
    require(res["architecture"] == architecture, "container platform differs")
    require(
        res["wheel_sha256"] == MANIFEST["wheel_sha256"], "built wheel digest differs"
    )
    return res
