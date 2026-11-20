"""Stage or audit the pinned public C# source corpus without upstream builds."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

import public_corpus_summary as summary
from parity import read_json, write_json_atomic

RECEIPT = Path(__file__).with_name("public-csharp-pilot-qualification-20261120.json")
BUILT_COMMIT = "9084eeca7eb9350f028fa9a791b1f0f0ca395968"
NATIVE_TREE = "5d9ccd5cc837d3fb2105172bcbeccb7cfc0866bc"
ASSEMBLIES = {
    "fast-member": "FastMember",
    "guardclauses": "GuardClauses",
    "sharpziplib": "ICSharpCode.SharpZipLib",
    "stateless": "Stateless",
}
MATCH_KEYS = ("matched", "native_only", "reference_only")
BUILD_FLAGS = (
    "msbuild",
    "Pilot.csproj",
    "-t:Rebuild",
    "-m:1",
    "-nr:false",
    "-nologo",
    "-v:normal",
)


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def require_disk(state):
    if shutil.disk_usage(state).free < 5 * 1024**3:
        raise RuntimeError("Refuse a new build or scan below 5 GiB free.")


def git(directory, *args):
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "submodule.recurse=false",
            "--git-dir",
            str(directory),
            *args,
        ],
        env={
            "PATH": os.defpath,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
        timeout=120,
    )


def fetch(repos, projects):
    repos.mkdir(exist_ok=True)
    for name, row in projects.items():
        repository, commit = row["repository"], row["commit"]
        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository),
            "invalid GitHub path",
        )
        require(re.fullmatch(r"[0-9a-f]{40}", commit), "full Git commit required")
        directory = repos / name
        directory.mkdir()
        git(directory, "init", "--quiet", "--bare", "--template=")
        git(
            directory,
            "fetch",
            "--depth=1",
            "--no-tags",
            "--no-recurse-submodules",
            f"https://github.com/{repository}.git",
            f"{commit}:refs/heads/pinned",
        )


def source_blobs(directory, row):
    require(
        git(directory, "rev-parse", "pinned").decode().strip() == row["commit"],
        "pinned commit mismatch",
    )
    require(
        git(directory, "rev-parse", "pinned^{tree}").decode().strip() == row["tree"],
        "pinned tree mismatch",
    )
    root = row["compile_source_root"]
    entries = git(directory, "ls-tree", "-rz", row["commit"], "--", root).split(b"\0")
    keys = set()
    records = []
    for entry in filter(None, entries):
        identity, path_bytes = entry.split(b"\t", 1)
        mode, kind, blob = identity.decode().split()
        path = path_bytes.decode()
        parts = PurePosixPath(path)
        if parts.suffix != ".cs":
            continue
        require(
            mode in {"100644", "100755"}
            and kind == "blob"
            and parts.is_relative_to(PurePosixPath(root))
            and parts.as_posix() == path
            and re.fullmatch(r"[\w./ -]+", path)
            and ".." not in parts.parts
            and parts.as_posix().casefold() not in keys,
            f"unsafe C# source path: {path}",
        )
        keys.add(path.casefold())
        data = git(directory, "cat-file", "blob", blob)
        data.decode("utf-8-sig")
        records.append(({"path": path, "blob": blob, "sha256": hash_bytes(data)}, data))
    require(
        [entry for entry, _ in records] == row["compile_files"],
        "Git C# inventory differs from receipt",
    )
    return records


def normalized_source(data):
    return re.sub(rb"\r\n?", b"\n", data.removeprefix(b"\xef\xbb\xbf"))


def verify_source_proof(row, records):
    proof = row["indexed_file_bytes"]
    missing = sorted({entry["path"] for entry, _ in records} - proof.keys())
    require(missing == row["not_indexed_by_sonarqube"], "C# scope gap differs")
    require(len(proof) == row["sonarqube"]["indexed_files"], "indexed C# count differs")
    require(row["native_files"] == len(records), "native C# count differs")
    changes = dict.fromkeys(
        (
            "bom_removed",
            "cr_normalized",
            "one_final_lf_added",
            "one_final_lf_removed",
            "verbatim",
        ),
        0,
    )
    for entry, data in records:
        path = entry["path"]
        if path in missing:
            require(
                path.endswith(".Designer.cs") and b"<auto-generated" in data,
                f"unexpected omitted file {path}",
            )
            continue
        expected_raw = normalized_source(data) + b"\n"
        require(
            proof[path]
            == {
                "git_input_sha256": entry["sha256"],
                "server_raw_sha256": hash_bytes(expected_raw),
                "raw_equivalence": "text_equal_after_bom_or_line_ending_normalization",
            },
            f"source readback proof differs for {path}",
        )
        changes["bom_removed"] += data.startswith(b"\xef\xbb\xbf")
        changes["cr_normalized"] += b"\r" in data
        changes["one_final_lf_added"] += 1
    require(
        changes == row["raw_source_readback"],
        "raw source normalization summary differs",
    )
    require(
        row["comparison"] == ("excluded" if missing else "same_source_files"),
        "scope status differs",
    )


def verify_totals(receipt, analyzed):
    scoped = [row for row in analyzed if row["comparison"] == "same_source_files"]
    totals = {
        key: sum(row["shared_parameters_primary_findings"][key] for row in scoped)
        for key in MATCH_KEYS
    }
    count = sum(row["sonarqube"]["indexed_files"] for row in scoped)
    require(
        len(scoped) == receipt["scopes_with_same_sources"],
        "identical scope count differs",
    )
    require(count == receipt["same_scope_files"], "identical scope file count differs")
    require(
        totals == receipt["source_scan_comparison_shared_parameters"],
        "shared findings tally differs",
    )
    require(
        receipt["compiler_parity_qualified"] is False, "compiler parity outside scope"
    )
    require(
        receipt["enterprise_parity_qualified"] is False,
        "Enterprise parity outside scope",
    )
    return {
        "identical_scopes": len(scoped),
        "identical_files": count,
        "primary_findings": totals,
    }


def verify_sources(state, receipt):
    projects = receipt["projects"]
    require(projects.keys() == ASSEMBLIES.keys(), "unexpected C# corpus projects")
    records = {}
    for name, row in projects.items():
        records[name] = source_blobs(state / "repos" / name, row)
        verify_source_proof(row, records[name])
    return records


def refs_path(sdk):
    path = sdk / "packs/Microsoft.NETCore.App.Ref/10.0.11/ref/net10.0"
    require(
        (path / "System.Runtime.dll").is_file(),
        "missing .NET 10.0.11 reference assemblies",
    )
    return path


def write_project(root, row, refs, assembly):
    xml = ET.Element("Project", {"DefaultTargets": "Build"})
    props = ET.SubElement(xml, "PropertyGroup")
    values = {
        "AssemblyName": assembly,
        "RootNamespace": assembly,
        "OutputType": "Library",
        "OutputPath": "bin/",
        "BaseIntermediateOutputPath": "obj/",
        "TargetFrameworkIdentifier": ".NETCoreApp",
        "TargetFrameworkVersion": "v10.0",
        "_TargetFrameworkVersionWithoutV": "10.0",
        "TargetFrameworkMoniker": ".NETCoreApp,Version=v10.0",
        "_TargetFrameworkDirectories": str(refs),
        "_FullFrameworkReferenceAssemblyPaths": str(refs),
        "FrameworkPathOverride": str(refs),
        "AssemblySearchPaths": "{HintPathFromItem}",
        "GenerateTargetFrameworkAttribute": "false",
        "ImportDirectoryBuildProps": "false",
        "ImportDirectoryBuildTargets": "false",
        "ImportDirectoryPackagesProps": "false",
        "ImportUserLocationsByWildcardBeforeMicrosoftCommonTargets": "false",
        "ImportUserLocationsByWildcardAfterMicrosoftCommonTargets": "false",
        "ImportByWildcardBeforeMicrosoftCommonTargets": "false",
        "ImportByWildcardAfterMicrosoftCommonTargets": "false",
        "NoStdLib": "true",
        "LangVersion": "latest",
        "AllowUnsafeBlocks": "true",
        "Deterministic": "true",
        "DefineConstants": ";".join(row["defines"]),
        "UseSharedCompilation": "false",
        "SonarQubeTestProject": "false",
        "ProjectGuid": "{"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, row["repository"]))
        + "}",
    }
    for key, value in values.items():
        ET.SubElement(props, key).text = value
    items = ET.SubElement(xml, "ItemGroup")
    for entry in row["compile_files"]:
        ET.SubElement(items, "Compile", {"Include": entry["path"]})
    for dll in sorted(refs.glob("*.dll")):
        item = ET.SubElement(items, "Reference", {"Include": dll.stem})
        ET.SubElement(item, "HintPath").text = str(dll)
        ET.SubElement(item, "Private").text = "false"
    ET.SubElement(
        xml, "Import", {"Project": "$(MSBuildToolsPath)/Microsoft.CSharp.targets"}
    )
    integration = ".sonarqube/bin/targets/SonarQube.Integration.targets"
    condition = f"Exists('{integration}')"
    sonar_props = ET.SubElement(xml, "PropertyGroup", {"Condition": condition})
    ET.SubElement(
        sonar_props, "SonarQubeTempPath"
    ).text = "$(MSBuildProjectDirectory)/.sonarqube"
    ET.SubElement(xml, "Import", {"Project": integration, "Condition": condition})
    ET.indent(xml)
    ET.ElementTree(xml).write(
        root / "Pilot.csproj", encoding="utf-8", xml_declaration=True
    )


def stage(state, sdk, projects, records):
    refs = refs_path(sdk)
    (state / "stage").mkdir()
    (state / "captures").mkdir()
    for name, row in projects.items():
        root = state / "stage" / name
        root.mkdir()
        for entry, data in records[name]:
            path = root / entry["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        write_project(root, row, refs, ASSEMBLIES[name])
        folder = state / "captures" / name
        folder.mkdir()
        write_json_atomic(
            folder / "staged-project.json",
            {"sha256": summary.digest(root / "Pilot.csproj")},
        )


def staged_inputs(root, row):
    expected = {entry["path"]: entry["sha256"] for entry in row["compile_files"]}
    sources = (root / row["compile_source_root"]).rglob("*.cs")
    require(
        {f.relative_to(root).as_posix() for f in sources} == expected.keys(),
        "staged source scope differs",
    )
    for path, digest in expected.items():
        source = root / path
        require(
            source.resolve() == source and summary.digest(source) == digest,
            f"staged source differs: {path}",
        )
    return expected


def verified_boundaries(commit):
    for candidate in (commit, BUILT_COMMIT):
        observed = subprocess.check_output(
            ["git", "-C", str(summary.REPO), "rev-parse", f"{candidate}^{{tree}}"],
            text=True,
        ).strip()
        require(observed == NATIVE_TREE, "native provenance trees differ")
    return summary.verified_boundaries(commit)[0]


def shared_tally(
    folder, root, key, reference_index, indexed, effective, catalog, boundaries
):
    findings = summary.finding_comparison(
        folder,
        effective,
        catalog,
        boundaries,
        root,
        read_json(folder / "native.json"),
        read_json(folder / "issues.json"),
        {"project_key": key},
        reference_index,
        indexed,
        set(reference_index),
    )
    return findings["shared_files"]["by_class"]["shared_equal_declared_parameters"]


def verify_execution(folder, step, verify_build=False):
    receipt = read_json(folder / f"{step}-execution.json")
    require(receipt["exit_code"] == 0, f"failed execution: {step}")
    for stream in ("stdout", "stderr"):
        require(
            summary.digest(folder / f"{step}.{stream}") == receipt[f"{stream}_sha256"],
            f"modified log: {step}",
        )
    if verify_build:
        require(tuple(receipt["argv"][1:]) == BUILD_FLAGS, "unexpected build command")


def indexed_sources(folder, root, expected):
    native_index = summary.source_indexes(folder, root, "native")
    reference_index = summary.source_indexes(folder, root, "reference")
    require(native_index == expected, "native source inventory differs")
    require(
        all(expected.get(path) == digest for path, digest in reference_index.items()),
        "reference used other source bytes",
    )
    indexed = read_json(folder / "indexed-files.json")
    require(
        sorted(item["path"] for item in indexed) == sorted(reference_index),
        "indexed paths differ",
    )
    require(
        all(item.get("language") == "cs" for item in indexed),
        "unexpected indexed language",
    )
    return reference_index, indexed


def verify_compute(task, observed, key):
    require(
        (task["status"], task["id"], task["analysisId"], task["componentKey"])
        == ("SUCCESS", observed["compute_task"], observed["analysis_id"], key),
        f"historical compute receipt differs: {key}",
    )


def verify_capture(state, name, row, effective, catalog, boundaries):
    root, folder = state / "stage" / name, state / "captures" / name
    expected = staged_inputs(root, row)
    require(
        summary.digest(root / "Pilot.csproj") == row["minimal_project_sha256"],
        f"historical project changed: {name}",
    )
    for step in (
        "bare-build-v2",
        "scanner-begin",
        "scanner-build",
        "scanner-end",
        "native",
    ):
        verify_execution(folder, step, step in {"bare-build-v2", "scanner-build"})
    require(
        "SonarAnalyzer.CSharp.dll" in (folder / "scanner-build.stdout").read_text(),
        "missing Roslyn analyzer",
    )
    compute = read_json(folder / "compute-engine.json")["task"]
    observed = row["sonarqube"]
    key = f"hq-public-csharp-pilot-20261120-{name}"
    verify_compute(compute, observed, key)
    proof = read_json(folder / "indexed-source-proof.json")
    require(
        proof
        == {
            "files": row["indexed_file_bytes"],
            "not_indexed": row["not_indexed_by_sonarqube"],
        },
        "stored source proof differs",
    )
    reference_index, indexed = indexed_sources(folder, root, expected)
    require(
        reference_index.keys() == proof["files"].keys(),
        "reference did not index the claimed files",
    )
    native = read_json(folder / "native.json")
    require(
        native["project"]["complete"] and read_json(folder / "native.stdout") == native,
        "incomplete native report",
    )
    require(
        native["parity"]["semantic_context"]["csharp"]
        == row["native_compiler_context"]
        == "missing",
        "unexpected native compiler context",
    )
    require(
        len(read_json(folder / "issues.json")) == observed["issues"],
        "issue count differs",
    )
    require(
        len(read_json(folder / "hotspots.json")) == observed["hotspots"],
        "hotspot count differs",
    )
    if row["comparison"] == "same_source_files":
        tally = shared_tally(
            folder, root, key, reference_index, indexed, effective, catalog, boundaries
        )
        require(
            tally == row["shared_parameters_primary_findings"],
            f"shared findings differ: {name}",
        )


def verify_retained_tools(state, expected):
    retained = read_json(state / "tools.json")
    for key, value in retained.items():
        if key != "sonarqube":
            require(value == expected[key], f"historical tool differs: {key}")
    reference = retained["sonarqube"]
    require(
        reference["server"]["version"] == expected["community_build"],
        "historical reference differs",
    )
    require(
        reference["server_image"] == expected["server_image"],
        "historical image differs",
    )
    analyzer = state / "tmp/.sonarqube/resources"
    digests = {
        summary.digest(path) for path in analyzer.rglob("SonarAnalyzer.CSharp.dll")
    }
    require(
        digests == {expected["sonar_roslyn_analyzer_sha256"]},
        "historical analyzer differs",
    )


def load_comparison(effective_path, catalog_path, commit):
    return (
        read_json(effective_path)["profiles"],
        {row["external_key"]: row["rule_type"] for row in read_json(catalog_path)},
        verified_boundaries(commit),
    )


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    phases = parser.add_subparsers(dest="phase", required=True)
    phases.add_parser(
        "fetch", help="Fetch exact public Git objects into new bare repositories"
    )
    phases.add_parser(
        "verify",
        help="Verify public source hashes and the expected source transformations",
    )
    staging = phases.add_parser(
        "stage", help="Write isolated projects without running MSBuild"
    )
    staging.add_argument("--sdk", type=Path, required=True)
    audit = phases.add_parser(
        "audit", help="Recompute figures from the retained private captures"
    )
    audit.add_argument("--effective", type=Path, required=True)
    audit.add_argument("--native-catalog", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    receipt = read_json(RECEIPT)
    projects = receipt["projects"]
    if args.phase == "fetch":
        state.mkdir(parents=True, exist_ok=True)
        fetch(state / "repos", projects)
    records = verify_sources(state, receipt)
    if args.phase == "stage":
        stage(state, args.sdk.resolve(), projects, records)
    elif args.phase == "audit":
        verify_retained_tools(state, receipt["tools"])
        comparison = load_comparison(
            args.effective,
            args.native_catalog,
            receipt["tools"]["native_at_verified_main"],
        )
        for name, row in projects.items():
            verify_capture(state, name, row, *comparison)
    print(
        {
            "pinned_compile_files": sum(map(len, records.values())),
            "reference_indexed_files": sum(
                row["sonarqube"]["indexed_files"] for row in projects.values()
            ),
            **verify_totals(receipt, projects.values()),
        }
    )


if __name__ == "__main__":
    main()
