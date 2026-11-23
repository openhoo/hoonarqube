"""Executed inside the offline test container, with the pinned source mounted read-only."""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

JOB = Path("/job")
SOURCE = JOB / "source"
PYTHON = str(JOB / "venv/bin/python")


def run(*command, env=None):
    proc = subprocess.run(
        command,
        cwd=SOURCE,
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        timeout=120,
    )
    if proc.returncode:
        raise ValueError(
            f"{command[0]} exited {proc.returncode}: {(proc.stdout + proc.stderr)[-1500:]}"
        )
    return proc.stdout


def build():
    run("python", "-m", "venv", JOB / "venv")
    run(
        PYTHON,
        "-m",
        "pip",
        "install",
        "--no-deps",
        *sorted(Path("/wheels").glob("*.whl")),
    )
    run(
        PYTHON,
        "-m",
        "pip",
        "wheel",
        "--no-deps",
        "--no-build-isolation",
        "--wheel-dir",
        "/job/dist",
        ".",
    )
    (wheel,) = (JOB / "dist").glob("blinker-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        for src in (SOURCE / "src/blinker").iterdir():
            if archive.read("blinker/" + src.name) != src.read_bytes():
                raise ValueError(f"wheel contains different bytes for {src.name}")
    run(PYTHON, "-m", "pip", "install", "--no-deps", wheel)
    imported = Path(
        run(PYTHON, "-c", "import blinker; print(blinker.__file__)").strip()
    )
    if not imported.is_relative_to(JOB / "venv/lib") or imported.parts[-3:] != (
        "site-packages",
        "blinker",
        "__init__.py",
    ):
        raise ValueError("tests would import from a different installation")
    run(PYTHON, "-m", "pip", "check")
    return hashlib.sha256(wheel.read_bytes()).hexdigest()


def suite(case, args, expected):
    cov = {"COVERAGE_FILE": str(JOB / (case + ".cov"))}
    log = run(
        PYTHON,
        "-m",
        "coverage",
        "run",
        "-p",
        "-m",
        "pytest",
        "-q",
        "-o",
        "cache_dir=/job/pytest",
        *args,
        env=cov,
    )
    if not re.search(rf"^{expected} passed in [0-9.]+s$", log, re.MULTILINE):
        raise ValueError(f"unexpected test result: {log[-500:]}")
    run(PYTHON, "-m", "coverage", "combine", "--keep", "/job", env=cov)
    path = JOB / (case + ".lcov")
    run(
        PYTHON, "-m", "coverage", "lcov", "--include=src/blinker/*", "-o", path, env=cov
    )
    return {
        "passed": expected,
        "lcov": base64.b64encode(path.read_bytes()).decode("ascii"),
    }


def main():
    shutil.copytree("/input", SOURCE)
    os.environ.update(
        HOME="/job",
        PIP_NO_INDEX="1",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    print(
        json.dumps(
            {
                "wheel_sha256": build(),
                "full": suite("full", [], 25),
                "focused": suite("focused", ["tests/test_context.py"], 4),
            }
        )
    )


if __name__ == "__main__":
    main()
