"""Replay the C# pilot against a caller-owned, isolated Community Build instance."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

import public_corpus_capture as capture
import public_csharp_pilot as pilot
from parity import read_json, read_secret_file, write_json_atomic
from real_project_suite import digest

ANALYZER_FAILURE = re.compile(r"\b(AD0001|CS8032|CS9057)\b")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def reference_settings(args, tools):
    server_id = (args.reference_state / "docker/server.id").read_text().strip()
    capture.SERVER = args.reference_container
    capture.NETWORK = args.reference_network
    pilot.require(
        tools["server_image"]["image"] == capture.SERVER_IMAGE,
        "unexpected reference image",
    )
    capture.verify_local_reference(args.reference_state)
    details = json.loads(subprocess.check_output(["docker", "inspect", server_id]))[0]
    pilot.require(
        not details["HostConfig"]["PortBindings"], "reference has published ports"
    )
    ip = ipaddress.IPv4Address(
        details["NetworkSettings"]["Networks"][args.reference_network]["IPAddress"]
    )
    pilot.require(
        ip.is_private and not ip.is_loopback, "reference has no isolated address"
    )
    token = read_secret_file(args.token_file).strip()
    pilot.require(bool(token), "reference token is empty")
    sonar = capture.DockerSonar(token + ":")
    status = sonar.request("/api/system/status")
    plugins = sonar.request("/api/plugins/installed")["plugins"]
    expected = tools["csharp_plugin"]
    csharp = next(plugin for plugin in plugins if plugin["key"] == "csharp")
    pilot.require(
        {key: csharp[key] for key in expected} == expected,
        "C# reference plugin differs",
    )
    pilot.require(
        (status["status"], status["version"]) == ("UP", tools["community_build"]),
        "Community Build version differs or reference is unavailable",
    )
    return sonar, f"http://{ip}:9000", token


def source_readback(sonar, url, component):
    query = urllib.parse.urlencode({"key": component["key"]})
    request = urllib.request.Request(
        f"{url}/api/sources/raw?{query}",
        headers={"Authorization": sonar.auth},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    limit = 4 * 1024 * 1024
    with opener.open(request, timeout=15) as response:
        raw = response.read(limit + 1)
    pilot.require(len(raw) <= limit, f"source readback too large: {component['path']}")
    return pilot.hash_bytes(raw)


def verify_readback(folder, row, sonar, url):
    indexed = read_json(folder / "indexed-files.json")
    evidence = row["indexed_file_bytes"]
    pilot.require(
        sorted(item["path"] for item in indexed) == sorted(evidence),
        "live file scope differs",
    )
    for item in indexed:
        reread = source_readback(sonar, url, item)
        pilot.require(
            reread == evidence[item["path"]]["server_raw_sha256"],
            f"live raw source differs: {item['path']}",
        )
    return len(indexed)


def isolated_env(args):
    home = args.state / "home"
    temporary = args.state / "tmp"
    home.mkdir(exist_ok=True)
    temporary.mkdir(exist_ok=True)
    return {
        "PATH": f"{args.sdk}{os.pathsep}{os.defpath}",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "DOTNET_ROOT": str(args.sdk),
        "DOTNET_CLI_HOME": str(home),
        "DOTNET_NOLOGO": "1",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
        "MSBuildEnableWorkloadResolver": "false",
        "JAVA_HOME": str(args.java.parents[1]),
        "SONAR_USER_HOME": str(args.state / "sonar-user-home"),
    }


def toolchain(args, tools, env):
    dotnet = args.sdk / "dotnet"
    compiler = args.sdk / f"sdk/{tools['dotnet_sdk']}/Roslyn/bincore/csc.dll"
    checks = {
        "native_sha256": args.binary,
        "scanner_package_sha256": args.scanner_package,
        "scanner_dll_sha256": args.scanner_dll,
        "dotnet_host_sha256": dotnet,
        "csharp_compiler_sha256": compiler,
    }
    for field, path in checks.items():
        pilot.require(digest(path) == tools[field], f"pinned tool differs: {field}")
    pilot.require(
        subprocess.check_output(
            [str(dotnet), "--version"], env=env, cwd=args.state, text=True, timeout=30
        ).strip()
        == tools["dotnet_sdk"],
        ".NET SDK differs",
    )
    java = subprocess.check_output(
        [str(args.java), "-version"],
        env=env,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    ).splitlines()[0]
    pilot.require(java == tools["java"], "Java differs")
    pilot.refs_path(args.sdk)


def run_logged(args, command, root, folder, step, env, token=""):
    pilot.require_disk(args.state)
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=env,
            text=True,
            errors="replace",
            capture_output=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{step} timed out") from None

    def redact(value):
        return value.replace(token, "[redacted]") if token else value

    for suffix, stream in (("stdout", result.stdout), ("stderr", result.stderr)):
        (folder / f"{step}.{suffix}").write_text(redact(stream), encoding="utf-8")
    write_json_atomic(
        folder / f"{step}-execution.json",
        {
            "argv": [redact(arg) for arg in command],
            "exit_code": result.returncode,
            "stdout_sha256": digest(folder / f"{step}.stdout"),
            "stderr_sha256": digest(folder / f"{step}.stderr"),
        },
    )
    pilot.require(result.returncode == 0, f"{step} failed: inspect the private capture")
    return redact(result.stdout)


def run_scanner(args, tools, row, key, root, folder, reference, env):
    sonar, url, token = reference
    pilot.require_disk(args.state)
    sonar.request(
        "/api/projects/create",
        {"project": key, "name": key, "visibility": "private"},
        post=True,
    )
    build = [str(args.sdk / "dotnet"), *pilot.BUILD_FLAGS]
    run_logged(args, build, root, folder, "bare-build", env)
    options = {
        "sonar.host.url": url,
        "sonar.scm.disabled": "true",
        "sonar.sourceEncoding": "UTF-8",
        "sonar.scanner.scanAll": "false",
        "sonar.scanner.skipJreProvisioning": "true",
        "sonar.scanner.javaExePath": str(args.java),
        "sonar.scanner.useSonarScannerCLI": "false",
        "sonar.projectBaseDir": str(root),
    }
    scanner = [str(args.sdk / "dotnet"), str(args.scanner_dll)]
    auth = "/d:sonar.token=" + token
    begin = run_logged(
        args,
        [
            *scanner,
            "begin",
            f"/k:{key}",
            f"/v:{row['commit']}",
            *[f"/d:{k}={v}" for k, v in options.items()],
            auth,
        ],
        root,
        folder,
        "scanner-begin",
        env,
        token,
    )
    version = re.search(r"SonarScanner for (?:\.NET|MSBuild)\s+(\S+)", begin)
    pilot.require(
        version and version[1] == tools["scanner_package_version"],
        "C# scanner version differs",
    )
    log = run_logged(args, build, root, folder, "scanner-build", env, token)
    pilot.require(
        "SonarAnalyzer.CSharp.dll" in log and not ANALYZER_FAILURE.search(log),
        "Roslyn analyzer did not run cleanly",
    )
    end = run_logged(
        args, [*scanner, "end", auth], root, folder, "scanner-end", env, token
    )
    capture.oracle.wait_for_compute_engine(end, sonar, folder)
    task = read_json(folder / "compute-engine.json")["task"]
    pilot.require(
        (task["status"], task["componentKey"]) == ("SUCCESS", key),
        "reference compute task differs",
    )
    capture.oracle.capture_reference({"project_key": key}, sonar, root, folder)
    return task


def verify_effective_csharp(folder, sonar, profile):
    key = profile["profile_key"]
    observed = sonar.pages(
        "/api/rules/search",
        {"qprofile": key, "activation": "true", "f": "actives,params"},
        "rules",
        folder,
        "effective-cs",
    )
    pilot.require(
        {row["key"] for row in observed} == profile["rules"].keys(),
        "live C# rule keys differ",
    )
    for page in sorted(folder.glob("effective-cs-page-*.json")):
        for rule, activations in read_json(page)["actives"].items():
            current = [
                {p["key"]: p["value"] for p in a["params"]}
                for a in activations
                if a["qProfile"] == key
            ]
            pilot.require(
                current == [profile["rules"][rule]["parameters"]],
                f"live C# rule parameters differ: {rule}",
            )


def run_project(args, tools, name, row, reference, env, comparison):
    root, folder = args.state / "stage" / name, args.state / "captures" / name
    project = root / "Pilot.csproj"
    expected = pilot.staged_inputs(root, row)
    project_sha = read_json(folder / "staged-project.json")["sha256"]
    key = f"{args.project_prefix}-{name}"
    pilot.require(
        not (root / ".sonarqube").exists() and digest(project) == project_sha,
        "capture needs a fresh staged project",
    )
    task = run_scanner(args, tools, row, key, root, folder, reference, env)
    pilot.require_disk(args.state)
    native = capture.run_native(
        {"sources": list(expected), "exclude": []}, root, folder, args.binary
    )
    pilot.require(native["status"] == "complete", "native scan incomplete")
    pilot.require(
        pilot.staged_inputs(root, row) == expected and digest(project) == project_sha,
        "C# input changed during scan",
    )
    ref_index, indexed = pilot.indexed_sources(folder, root, expected)
    pilot.require(
        sorted(expected.keys() - ref_index.keys()) == row["not_indexed_by_sonarqube"],
        "replay indexed different files",
    )
    spec = read_json(folder / "native.json")["parity"]["semantic_context"]
    pilot.require(spec["csharp"] == "missing", "unexpected native compiler context")
    sonar, url, _ = reference
    verify_effective_csharp(folder, sonar, comparison[0]["cs"])
    count = verify_readback(folder, row, sonar, url)
    result = {
        "reference_indexed_files": count,
        "native_files": len(expected),
        "compute_task": task["id"],
        "analysis_id": task["analysisId"],
    }
    if ref_index == expected:
        tally = pilot.shared_tally(folder, root, key, ref_index, indexed, *comparison)
        pilot.require(
            tally == row["shared_parameters_primary_findings"],
            "replay reported different primary findings",
        )
        result["shared_parameters_primary_findings"] = tally
    write_json_atomic(folder / "live-replay.json", result)
    print(name, result, flush=True)


def replay(args, receipt, env):
    tools = receipt["tools"]
    pilot.require(
        re.fullmatch(r"[a-z][a-z0-9-]{0,60}", args.project_prefix),
        "invalid project prefix",
    )
    pilot.require_disk(args.state)
    reference = reference_settings(args, tools)
    effective = read_json(args.effective)["profiles"]
    if any(
        not rule_set["builtin"] or not rule_set["default"]
        for rule_set in effective.values()
    ):
        raise ValueError("replay requires built-in default profiles")
    output = subprocess.check_output(
        [str(args.binary), "rules", "list", "--json"], cwd=args.state, timeout=30
    )
    catalog = {row["external_key"]: row["rule_type"] for row in json.loads(output)}
    comparison = (
        effective,
        catalog,
        pilot.verified_boundaries(tools["native_at_verified_main"]),
    )
    for name, row in receipt["projects"].items():
        run_project(args, tools, name, row, reference, env, comparison)
    cache = args.state / "tmp/.sonarqube/resources"
    analyzers = {digest(path) for path in cache.rglob("SonarAnalyzer.CSharp.dll")}
    pilot.require(
        analyzers == {tools["sonar_roslyn_analyzer_sha256"]},
        "Roslyn analyzer assembly differs",
    )


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--state", type=lambda path: Path(path).resolve(), required=True)
    phases = cli.add_subparsers(dest="phase", required=True)
    readback = phases.add_parser(
        "readback", help="Verify live raw API results against historical hashes"
    )
    check = phases.add_parser(
        "check-tools", help="Verify the .NET, Java, scanner and native toolchain"
    )
    live = phases.add_parser(
        "capture", help="Rebuild and scan newly staged projects sequentially"
    )
    for phase in (readback, live):
        phase.add_argument("--reference-state", type=Path, required=True)
        phase.add_argument("--reference-container", required=True)
        phase.add_argument("--reference-network", required=True)
        phase.add_argument("--token-file", type=Path, required=True)
    for phase in (check, live):
        for option in ("sdk", "scanner-package", "scanner-dll", "java", "binary"):
            phase.add_argument(
                f"--{option}", type=lambda path: Path(path).resolve(), required=True
            )
    live.add_argument("--project-prefix", required=True)
    live.add_argument("--effective", required=True, type=Path)
    return cli


def main():
    os.umask(0o077)
    args = parser().parse_args()
    receipt = read_json(pilot.RECEIPT)
    if args.phase == "readback":
        sonar, url, _ = reference_settings(args, receipt["tools"])
        total = 0
        for name, row in receipt["projects"].items():
            observed = row["sonarqube"]
            task = sonar.request("/api/ce/task", {"id": observed["compute_task"]})[
                "task"
            ]
            pilot.verify_compute(
                task, observed, f"hq-public-csharp-pilot-20261120-{name}"
            )
            total += verify_readback(args.state / "captures" / name, row, sonar, url)
        print(f"verified {total} live source hashes")
        return
    env = isolated_env(args)
    toolchain(args, receipt["tools"], env)
    if args.phase == "capture":
        pilot.verify_sources(args.state, receipt)
        replay(args, receipt, env)
    else:
        print(
            "verified pinned .NET, Java, scanner package, scanner assembly and native executable"
        )


if __name__ == "__main__":
    main()
