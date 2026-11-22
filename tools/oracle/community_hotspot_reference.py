"""Read and verify the pinned Redux Community analyses; never change a server setting."""

import argparse
import hashlib
import json
from pathlib import Path

from community_hotspot_replay import BASE, HEAD, SOURCE, DIGESTS
from community_rule_types import VERSION, TABLE, ROOT, require
from parity import read_secret_file, validate_search_page, write_json_atomic
import public_corpus_capture as containers
from real_project_suite import Sonar

RULE = "javascript:S2245"


def verify_profile(get, pages, project):
    files = pages(
        "files", "components/tree", "components", component=project, qualifiers="FIL"
    )
    require(
        [(f["path"], f["language"]) for f in files] == [(SOURCE, "js")],
        "wrong source scope",
    )
    profiles = get(
        "profiles", "qualityprofiles/search", project=project, language="js"
    )["profiles"]
    require(
        len(profiles) == 1
        and profiles[0]["name"] == "Sonar way"
        and profiles[0]["isBuiltIn"]
        and profiles[0]["isDefault"],
        "wrong JS profile",
    )
    profile = profiles[0]
    rules = pages(
        "rules", "rules/search", "rules", activation="true", qprofile=profile["key"]
    )
    require(len(rules) == profile["activeRuleCount"], "incomplete rules")
    table = (ROOT / "catalog/reference" / TABLE).read_text().splitlines()[1:]
    expected = {
        k: t
        for lang, k, t in (line.split("\t") for line in table)
        if lang == "javascript" and t != "NOT_ACTIVE"
    }
    require(
        {r["key"]: r["type"] for r in rules} == expected,
        "live rule types differ from captured profile",
    )
    rule = get("rule", "rules/show", key=RULE)["rule"]
    require(
        rule["key"] == RULE and rule["type"] == expected[RULE] == "VULNERABILITY",
        "wrong rule type",
    )
    return files, profile, rule


def task_ids(get, project, base_task, task):
    ids = []
    for label, tid in (("base", base_task), ("head", task)):
        row = get(label + "-task", "ce/task", id=tid)["task"]
        require(
            row["componentKey"] == project
            and row["id"] == tid
            and row["status"] == "SUCCESS"
            and row["type"] == "REPORT",
            "wrong compute task",
        )
        ids.append(row["analysisId"])
    require(len(set(ids)) == 2, "repeated analysis")
    return ids


def verify(api, output, project, branch, base_task, task, server_version):
    require(server_version == VERSION, "unsupported reference version")
    output.mkdir(parents=True, exist_ok=True)
    hashes = {}

    def record(label, value):
        dest = output / (label + ".json")
        write_json_atomic(dest, value)
        hashes[dest.name] = hashlib.sha256(dest.read_bytes()).hexdigest()
        return value

    def get(label, endpoint, **params):
        return record(label, api.request("/api/" + endpoint, params))

    def pages(label, endpoint, field, **params):
        items = []
        seen = set()
        total = size = None
        for page in range(1, 1001):
            data = get(f"{label}-{page}", endpoint, **params, p=page, ps=500)
            more, total, size, done = validate_search_page(
                data,
                field,
                page,
                expected_total=total,
                expected_page_size=size,
                seen_keys=seen,
            )
            items.extend(more)
            if done:
                return items
        raise ValueError("paging limit exceeded")

    server = get("server", "system/status")
    require(server["version"] == VERSION and server["status"] == "UP", "wrong server")
    ids = task_ids(get, project, base_task, task)

    def history(label):
        return pages(label, "project_analyses/search", "analyses", project=project)

    records = history("analysis")
    require(
        [(a["key"], a["revision"]) for a in records[:2]]
        == [(ids[1], HEAD), (ids[0], BASE)],
        "inventory is current-project state; latest two analyses must be the pinned pair",
    )
    period = get("period", "new_code_periods/show", project=project, branch=branch)
    require(
        period["type"] == "SPECIFIC_ANALYSIS"
        and period["value"] == ids[0]
        and period["branchKey"] == branch
        and period["projectKey"] == project,
        "unbound baseline",
    )
    gate = get("head-gate", "qualitygates/project_status", analysisId=ids[1])[
        "projectStatus"
    ]
    require(
        gate["period"]["mode"] == period["type"]
        and gate["period"]["parameter"] == ids[0],
        "gate used a different baseline",
    )
    base_gate = get("base-gate", "qualitygates/project_status", analysisId=ids[0])[
        "projectStatus"
    ]
    assigned = get("assignment", "qualitygates/get_by_project", project=project)[
        "qualityGate"
    ]["name"]
    config = get("gate-config", "qualitygates/show", name=assigned)
    require(
        assigned == "Sonar way"
        and config["isBuiltIn"]
        and ("new_security_hotspots_reviewed", "LT", "100")
        in [(r["metric"], r["op"], r["error"]) for r in config["conditions"]],
        "wrong assigned gate",
    )
    get(
        "small-change",
        "settings/values",
        component=project,
        keys="sonar.qualitygate.ignoreSmallChanges",
    )
    files, profile, rule = verify_profile(get, pages, project)
    issues = pages("issues", "issues/search", "issues", components=project)
    new = pages(
        "new-issues",
        "issues/search",
        "issues",
        components=project,
        inNewCodePeriod="true",
    )
    hotspots = pages("hotspots", "hotspots/search", "hotspots", project=project)
    new_hotspots = pages(
        "new-hotspots",
        "hotspots/search",
        "hotspots",
        project=project,
        inNewCodePeriod="true",
    )
    require(all(i["project"] == project for i in issues + new), "issue outside project")
    lines = sorted(
        (i["line"], i["type"], i["creationDate"])
        for i in issues
        if i["rule"] == RULE and i["component"] == files[0]["key"]
    )
    require(
        [(line, kind) for line, kind, _ in lines]
        == [(8, "VULNERABILITY"), (9, "VULNERABILITY")],
        "reference Redux findings changed",
    )
    measures = get(
        "measures",
        "measures/component",
        component=project,
        metricKeys="new_lines,new_security_hotspots,new_security_hotspots_reviewed,new_violations",
    )["component"]
    require(
        measures["key"] == project and not hotspots and not new_hotspots,
        "wrong hotspot population",
    )
    require(
        len(issues) == 4 and not new and measures["measures"],
        "Redux Community issue population changed",
    )
    actual = {m["metric"]: m["period"]["value"] for m in measures["measures"]}
    require(
        actual
        == {"new_lines": "0", "new_security_hotspots": "0", "new_violations": "0"},
        "unexpected candidate measures or hotspot percentage",
    )
    require(
        gate["status"] == "OK"
        and gate["ignoredConditions"] is False
        and gate["conditions"]
        == [
            {
                "status": "OK",
                "metricKey": "new_violations",
                "comparator": "GT",
                "errorThreshold": "0",
                "actualValue": "0",
            }
        ],
        "observed Redux reference gate changed",
    )
    require(history("analysis-final") == records, "project changed during readback")
    receipt = {
        "server_version": VERSION,
        "repository": "reduxjs/redux",
        "project": project,
        "branch": branch,
        "revisions": [BASE, HEAD],
        "source": SOURCE,
        "public_source_sha256": DIGESTS,
        "ce_task_ids": [base_task, task],
        "analysis_ids": ids,
        "reference_profile": profile["key"],
        "rule": RULE,
        "rule_type": rule["type"],
        "occurrences": lines,
        "total_issues": len(issues),
        "new_issues": len(new),
        "hotspots": len(hotspots),
        "new_hotspots": len(new_hotspots),
        "new_code_period": period,
        "base_gate": base_gate,
        "candidate_gate": gate,
        "measures": measures["measures"],
        "inputs_sha256": hashes,
    }
    write_json_atomic(output / "receipt.json", receipt)
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    server = p.add_mutually_exclusive_group(required=True)
    server.add_argument("--url")
    server.add_argument("--container")
    for name in ("project", "branch", "base-task", "task", "server-version"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--token-file", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = vars(p.parse_args())
    token = read_secret_file(args.pop("token_file")).strip()
    container = args.pop("container")
    url = args.pop("url")
    if container:
        containers.SERVER = container
        api = containers.DockerSonar(token + ":")
    else:
        api = Sonar(url, token)
    receipt = verify(api, **args)
    print(
        json.dumps(
            {
                k: receipt[k]
                for k in (
                    "analysis_ids",
                    "new_issues",
                    "new_hotspots",
                    "candidate_gate",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
