"""Reconstruct the public reference contract from archived Community responses."""

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path


def read(path):
    return json.loads(path.read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pick(row, keys):
    return {key: row[key] for key in keys.split()}


def keyed(rows, key):
    result = {row[key]: row for row in rows}
    need(len(rows) == len(result), "duplicate " + key)
    return result


def by_quality(values):
    return {
        name: v["severity"]
        for name, v in sorted(keyed(values, "softwareQuality").items())
    }


def effective(page, meta, profile):
    rules, definitions = keyed(page["rules"], "key"), keyed(meta["rules"], "key")
    need(set(rules) == set(definitions) == set(page["actives"]), "rule set changed")
    need(
        page["p"] == meta["p"] == 1
        and len(rules) == page["total"] == meta["total"] == 200,
        "partial rule page",
    )
    result = {}
    for key in sorted(rules):
        (activation,) = page["actives"][key]
        rule = definitions[key]
        need(
            activation["qProfile"] == profile
            and key.startswith("javascript:")
            and rule["lang"] == "js",
            "foreign rule",
        )
        impacts = by_quality(activation["impacts"])
        need(
            rule["type"] == rules[key]["type"]
            and impacts
            == by_quality(rules[key]["impacts"])
            == by_quality(rule["impacts"]),
            "rule impacts changed",
        )
        result[key] = dict(
            **pick(rule, "name type scope status"),
            clean_code_attribute=rule.get("cleanCodeAttribute"),
            severity=activation["severity"],
            impacts=impacts,
            parameters={
                k: v["value"]
                for k, v in sorted(keyed(activation["params"], "key").items())
            },
            inherited=activation["inherit"],
            prioritized=activation["prioritizedRule"],
        )
    return result


def ce(path, project, revision):
    t = read(path / "compute-engine.json")["task"]
    run = read(path / "scanner-execution.json")
    need(
        t["status"] == "SUCCESS"
        and t["componentKey"] == project
        and run["exit_code"] == 0,
        "unsuccessful analysis",
    )
    need(
        "-Dsonar.projectKey=" + project in run["argv"]
        and "-Dsonar.scm.revision=" + revision in run["argv"],
        "scanner revision or project mismatch",
    )
    (image,) = [
        x for x in run["argv"] if x.startswith("sonarsource/sonar-scanner-cli:")
    ]
    return dict(
        scanner_image=image,
        project=project,
        task=t["id"],
        analysis=t["analysisId"],
        revision=revision,
        completed=t["executedAt"],
    )


def commander(directory, profile):
    result = []
    for name in ("b51c0ea3-broad", "987f2896-focused"):
        path = directory / name
        pair, classification = (
            read(path / "comparison.json"),
            read(path / "classification.json"),
        )
        need(
            read(path / "contract.json")["profile"]
            == pair["profile"]
            == classification["profile"]
            == profile,
            "Commander profile drift",
        )
        project = read(path / "project.json")["key"]
        stages = []
        for stage in ("base", "candidate"):
            root = path / stage
            source = read(root / "source.json")
            proof = ce(root, project, source["revision"])
            need(
                source["revision"] == pair[stage]
                and len(source["file_sha256"]) == pair["source_files"] == 7,
                "Commander source drift",
            )
            stages.append(
                dict(**proof, tree=source["tree"], files=source["file_sha256"])
            )
        ids = [x["analysis"] for x in stages]
        need(
            ids == pair["analysis_ids"]
            and classification["analysis"] == ids[1]
            and classification["revision"] == pair["candidate"],
            "Commander analysis mismatch",
        )
        gate = read(path / "candidate/gate.json")
        values = keyed(gate["conditions"], "metricKey")
        period = read(path / "native/period.json")
        need(
            gate == pair["reference_gate"]
            and gate["period"]["parameter"] == period["analysis_id"] == ids[0]
            and period["revision"] == stages[0]["revision"],
            "Commander baseline drift",
        )
        need(
            values["new_violations"]["actualValue"] == "0"
            and classification["reference_new_issues"]
            == classification["reference_new_hotspots"]
            == classification["active_count"]
            == 0,
            "unexpected reference finding",
        )
        need(
            all(not f["in_reference_profile"] for f in classification["native_new"]),
            "unexpected activated historical finding",
        )
        result.append(
            dict(
                label=name,
                repository=pair["repository"],
                stages=stages,
                period=period,
                reference_new_issues=0,
                reference_new_hotspots=0,
                legacy_new_issues=classification["counts"],
                coverage_sha256=pair["coverage_sha256"],
                gate=pick(gate, "status ignoredConditions"),
                reference_new_coverage=values["new_coverage"]["actualValue"],
            )
        )
    return result


def observations(issues, hotspots, project, inventory):
    need(
        issues["paging"]["total"] == len(issues["issues"])
        and hotspots["paging"]["total"] == len(hotspots["hotspots"]),
        "truncated observations",
    )
    rows = []
    for item in issues["issues"]:
        path = item["component"].removeprefix(project + ":")
        need(
            path in inventory and item["component"] == project + ":" + path,
            "observation out of scope",
        )
        loc = item["textRange"]
        rows.append(
            dict(
                path=path,
                rule=item["rule"],
                location=[
                    loc[k] for k in ("startLine", "startOffset", "endLine", "endOffset")
                ],
                **pick(item, "message severity type"),
                impacts={
                    key: val["severity"]
                    for key, val in sorted(
                        keyed(item["impacts"], "softwareQuality").items()
                    )
                },
            )
        )
    need(not hotspots["hotspots"], "this corpus needs a separate hotspot oracle")
    return sorted(
        rows, key=lambda x: (x["path"], x["location"], x["rule"], x["message"])
    )


def public_controls(cohort, captures, rules, profile, screened):
    core = cohort / "reference/npm-ini"
    source = read(core / "source.json")
    files = {key: value["sha256"] for key, value in source["source_inventory"].items()}
    need(
        files
        == {x["path"]: x["sha256"] for x in read(core / "reference-source-files.json")},
        "historical inventory",
    )
    project, revision = source["project_key"], source["commit"]
    old = dict(
        repository=source["repository"],
        revision=revision,
        tree=source["tree"],
        files=files,
        previous=True,
    )
    # This older collector bound the revision through its immutable Git inventory rather than -Dsonar.scm.revision.
    task = read(core / "compute-engine.json")["task"]
    scan = read(core / "scanner-execution.json")
    need(
        scan["exit_code"] == 0
        and task["status"] == "SUCCESS"
        and task["componentKey"] == project
        and "-Dsonar.projectKey=" + project in scan["argv"],
        "historical scan mismatch",
    )
    need(
        any(
            p["key"] == profile["key"]
            and p["rulesUpdatedAt"] == profile["rulesUpdatedAt"]
            for p in read(core / "profiles.json")["profiles"]
        ),
        "historical project profile",
    )
    need(
        {r["path"] for r in read(core / "indexed-files.json")} == set(files),
        "historical indexing",
    )
    old.update(
        project=project,
        task=task["id"],
        analysis=task["analysisId"],
        completed=task["executedAt"],
    )
    old["issues"] = observations(
        read(core / "issues-page-1.json"),
        read(core / "hotspots-page-1.json"),
        project,
        files,
    )
    result = [old]
    for name in (
        "debug-js-debug",
        "jshttp-negotiator",
        "caolan-async",
        "feross-buffer",
    ):
        d = captures / name
        (row,) = [
            r for r in screened if r["repo"]["full_name"].replace("/", "-") == name
        ]
        meta = row["repo"]
        need(
            not any(meta[k] for k in ("private", "fork", "archived")),
            "not a primary public repository",
        )
        for stage in ("before", "after"):
            p = read(d / f"profile-{stage}.json")
            need(
                pick(p, "key name activeRuleCount rulesUpdatedAt") == profile
                and p["isBuiltIn"]
                and p["isDefault"],
                "project profile drift",
            )
            need(
                effective(
                    read(d / f"rules-{stage}.json"),
                    read(d / f"meta-{stage}.json"),
                    p["key"],
                )
                == rules,
                "effective rules changed",
            )
        task = read(d / "compute-engine.json")["task"]
        project = task["componentKey"]
        receipt = ce(d, project, row["commit"])
        history = read(d / "analysis.json")
        need(
            history["key"] == receipt["analysis"]
            and history["revision"] == row["commit"] == history["projectVersion"],
            "public analysis revision",
        )
        files = {row["file"]: row["sha256"]}
        idx = read(d / "indexed.json")
        need(
            idx["paging"]["total"] == len(files)
            and {c["path"] for c in idx["components"] if c["language"] == "js"}
            == set(files),
            "index mismatch",
        )
        result.append(
            dict(
                repository=meta["full_name"],
                github_id=meta["id"],
                previous=row["previous"],
                tree=row["tree"],
                files=files,
                **receipt,
                issues=observations(
                    read(d / "issues.json"), read(d / "hotspots.json"), project, files
                ),
            )
        )
    return result


def inventory(directory, controls):
    names = [
        "history-canonical.json",
        "candidates-canonical.json",
        "exclusion-inventory.json",
    ]
    evidence = {name: read(directory / name) for name in names}
    historic = (
        {key.casefold() for key in evidence[names[0]]}
        | {key.casefold() for key in evidence[names[1]]}
        | {key.casefold() for key in evidence[names[2]]["repositories"]}
    )
    for row in controls:
        need(
            row["previous"] == (row["repository"].casefold() in historic),
            "incorrect claim of a new repository",
        )
    return dict(
        count=len(historic),
        sha256={name: digest((directory / name).read_bytes()) for name in names},
    )


def freeze(args):
    c, d = args.cohort, args.commander
    membership = read(d / "js-core-membership.json")
    profile = read(d / "b51c0ea3-broad/contract.json")["profile"]
    metadata = read(c / "reference/npm-ini/active-js-page-1.json")
    rules = effective(
        read(c / "profiles/effective-js-page-1.json"), metadata, profile["key"]
    )
    need(
        rules
        == effective(
            read(c / "profiles-end/effective-js-page-1.json"), metadata, profile["key"]
        ),
        "cohort profile drift",
    )
    need(
        membership["profile"] == profile["key"]
        and {k: pick(v, "severity parameters") for k, v in rules.items()}
        == membership["rules"],
        "Commander membership differs",
    )
    env = read(c / "environment-contract.json")
    analyzer = read(c / "analyzer-artifacts.json")["javascript"]
    need(
        env == read(c / "environment-contract-end.json")
        and analyzer == read(c / "analyzer-artifacts-end.json")["javascript"],
        "environment changed",
    )
    final = read(args.captures / "environment-after.json")
    need(
        final["image"] == env["server_image"]["image"]
        and final["javascript_jar_sha256"] == analyzer["jar_sha256"]
        and final["container_id"] == (c / "docker/server.id").read_text().strip(),
        "reference server or analyzer changed",
    )
    declared = read(args.selection)
    need(
        declared
        == dict(
            schema_version=1,
            profile=profile["name"],
            profile_key=profile["key"],
            version=env["version"],
            server_image_digest=env["server_image"]["image"].split("@")[-1],
            javascript_analyzer_version=analyzer["version"],
            javascript_analyzer_sha256=analyzer["jar_sha256"],
            effective_rules_capture_sha256=digest(
                (c / "profiles/effective-js-page-1.json").read_bytes()
            ),
            active_keys=sorted(rules),
            parameters={
                k: v["parameters"] for k, v in rules.items() if v["parameters"]
            },
        ),
        "scanner selection file disagrees with independent effective reference",
    )
    pairs = commander(d, profile)
    controls = public_controls(c, args.captures, rules, profile, read(args.screened))
    stages = [stage for pair in pairs for stage in pair["stages"]] + controls[1:]
    start = datetime.fromisoformat(final["started"])
    need(
        all(
            r["scanner_image"] == env["scanner_image"]["image"]
            and datetime.fromisoformat(r["completed"]) > start
            for r in stages
        ),
        "scanner image changed or receipt predates current reference container",
    )
    ids = [s["analysis"] for p in pairs for s in p["stages"]] + [
        x["analysis"] for x in controls
    ]
    need(
        len(set(ids)) == len(ids)
        and len({p["stages"][0]["project"] for p in pairs}) == 2,
        "reused analyses or projects",
    )
    for control in controls:
        for hit in control["issues"]:
            r = rules[hit["rule"]]
            need(
                r["scope"] in ("MAIN", "ALL")
                and all(hit[k] == r[k] for k in ("type", "severity", "impacts")),
                "reported issue contradicts rule metadata",
            )
    return dict(
        schema_version=1,
        environment=dict(
            **pick(env, "version edition server_image scanner_image"),
            javascript=analyzer,
            reference_container_start=final["started"],
        ),
        profile=profile,
        rules=rules,
        scanner_membership_sha256=digest(args.selection.read_bytes()),
        source_inventory=inventory(args.history, controls),
        commander=pairs,
        controls=controls,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "cohort",
        "commander",
        "captures",
        "screened",
        "history",
        "selection",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    opts = parser.parse_args()
    opts.output.write_text(
        json.dumps(freeze(opts), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
