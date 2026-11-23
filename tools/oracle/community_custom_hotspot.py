"""Verify the recorded custom Java hotspot against its actual Community API responses."""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

ARCHIVE = "community-custom-hotspot-20261122.tar.gz"
DIGEST = "3a05e103c856c676d899acf0b95bef8fac6a5042c722a71e12b0f759ff50cfd0"
BASE = "8eff0a40639a3c010b2bf720ccf89f49844de067"
HEAD = "6a4979ba028a257401b9fdfcc23f42d9419fff6f"
BASE_ID = "398f6b00-2e1d-414c-adc2-2deea634faf4"
HEAD_ID = "4a72bdcb-4a89-415b-965d-baa666c1c82e"
PROJECT = "hq-custom-java-hotspot-commons-lang-20261122"
RULE = "java:hqunitrngreview20261122"
PACKAGE = "src/test/java/org/apache/commons/lang3/"
CONTROL = PACKAGE + "CharSetTest.java"
SOURCE = PACKAGE + "StringUtilsJoinBenchmark.java"
SOURCE_HASH = "61647662238b2431c67e6970b16dc4e6499236c46005ef247fe66f401ec59191"
CONTROL_HASH = "97fc1bca71f704289eb030f3a47f94cba37d8027457b60a46a8888327f1d4d93"
METRICS = {"security_hotspots_reviewed", "new_security_hotspots_reviewed"}


def require(predicate, problem):
    if not predicate:
        raise ValueError(problem)


def load(path):
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == DIGEST, "wrong capture archive"
    )
    data = {}
    with tarfile.open(path, "r:gz") as archive:
        for item in archive:
            require(
                item.isfile() and item.name.endswith(".json") and "/" not in item.name,
                "invalid capture member",
            )
            name = item.name.removesuffix(".json")
            require(
                name not in data and item.size <= 1024 * 1024,
                "duplicate or oversized member",
            )
            data[name] = json.load(archive.extractfile(item))
    return data


def verify_configuration(d):
    require(
        d["server"]["version"] == "26.9.0.129388" and d["server"]["status"] == "UP",
        "wrong server",
    )
    counts = {v["val"]: v["count"] for v in d["types-facet"]["facets"][0]["values"]}
    require(
        counts
        == {
            "CODE_SMELL": 2786,
            "BUG": 1011,
            "VULNERABILITY": 649,
            "SECURITY_HOTSPOT": 0,
        }
        and sum(counts.values()) == d["types-facet"]["total"],
        "wrong pre-custom catalog",
    )
    require(
        all(
            d[f"{lang}-all-hotspots"]["total"] == 0
            for lang in ["global", "js", "ts", "py", "cs", "java", "go", "rust", "ruby"]
        ),
        "installed hotspot found",
    )
    require(
        [(r["key"], r["type"]) for r in d["known-vulnerability"]["rules"]]
        == [("javascript:S2245", "VULNERABILITY")],
        "wrong positive rule search control",
    )
    rule = d["rule-created"]["rule"]
    require(
        (rule["key"], rule["templateKey"], rule["type"])
        == (RULE, "java:S4011", "SECURITY_HOTSPOT"),
        "wrong custom rule",
    )
    params = {p["key"]: p.get("defaultValue") for p in rule["params"]}
    require(
        params["className"] == "java.util.Random" and params["allOverloads"] == "true",
        "wrong constructor match",
    )
    require(
        d["create-hotspot"]["status"] == 200
        and d["create-hotspot"]["parameters"]["type"] == "SECURITY_HOTSPOT",
        "missing typed rule creation",
    )
    (default,) = d["java-default-before"]["profiles"]
    require(
        d["java-default-after"]["profiles"] == [default]
        and default["isDefault"]
        and default["isBuiltIn"]
        and (default["name"], default["language"], default["activeRuleCount"])
        == ("Sonar way", "java", 599)
        and d["default-active-custom"]["total"] == 0,
        "default profile changed",
    )
    (profile,) = d["custom-profile"]["profiles"]
    require(
        not profile["isBuiltIn"]
        and not profile["isDefault"]
        and profile["activeRuleCount"] == 1
        and profile["language"] == "java",
        "wrong project profile",
    )
    require(
        [(r["key"], r["type"]) for r in d["custom-active"]["rules"]]
        == [(RULE, "SECURITY_HOTSPOT")],
        "wrong custom activation",
    )
    gate = d["custom-gate"]
    require(
        not gate["isBuiltIn"]
        and d["project-gate-assignment"]["qualityGate"]["name"] == gate["name"],
        "wrong project gate",
    )
    require(
        {(x["metric"], x["op"], x["error"]) for x in gate["conditions"]}
        == {(k, "LT", "100") for k in METRICS},
        "wrong gate conditions",
    )


def verify_scope(d):
    hist = d["verified-history"]["analyses"]
    require(
        [(a["key"], a["revision"]) for a in hist[:2]]
        == [(HEAD_ID, HEAD), (BASE_ID, BASE)],
        "wrong analysis pair",
    )
    for label, rev, analysis_id, hashes in [
        ("base", BASE, BASE_ID, {CONTROL: CONTROL_HASH}),
        ("head", HEAD, HEAD_ID, {CONTROL: CONTROL_HASH, SOURCE: SOURCE_HASH}),
    ]:
        task = d[label + "-ce"]["task"]
        require(
            task["componentKey"] == PROJECT
            and task["status"] == "SUCCESS"
            and task["analysisId"] == analysis_id,
            "unverified analysis",
        )
        src = d[label + "-source"]
        require(
            src["repository"] == "apache/commons-lang"
            and src["revision"] == rev
            and {k: v["sha256"] for k, v in src["files"].items()} == hashes,
            "wrong public source",
        )
        tree = d[label + "-files"]
        require(
            tree["paging"]["total"] == len(hashes)
            and {(f["path"], f["language"]) for f in tree["components"]}
            == {(k, "java") for k in hashes},
            "wrong indexed scope",
        )
    period = d["head-gate"]["projectStatus"]["period"]
    require(
        period
        == {"mode": "SPECIFIC_ANALYSIS", "date": hist[1]["date"], "parameter": BASE_ID},
        "wrong new-code cutoff",
    )
    require(
        not d["base-hotspots-overall"]["paging"]["total"]
        and not d["base-hotspots-new"]["paging"]["total"]
        and not d["base-hotspots-overall"]["hotspots"]
        and not d["base-hotspots-new"]["hotspots"]
        and not d["base-gate"]["projectStatus"]["conditions"],
        "baseline is not empty",
    )


def verify_states(d):
    first = d["before-hotspot-643"]
    require(
        first["rule"]["key"] == RULE
        and first["line"] == 643
        and first["component"]["path"] == SOURCE
        and first["project"]["key"] == PROJECT,
        "wrong hotspot",
    )
    result = []
    for label, state, res, pct, current in [
        ("before", "TO_REVIEW", None, 0, "ERROR"),
        ("after-review-643", "REVIEWED", "SAFE", 100, "OK"),
        ("reopened", "TO_REVIEW", None, 0, "ERROR"),
    ]:
        for suffix in ("all", "new"):
            items = d[label + "-" + suffix]
            require(
                items["paging"]["total"] == 1
                and [
                    (h["key"], h["line"], h["status"], h.get("resolution"))
                    for h in items["hotspots"]
                ]
                == [(first["key"], 643, state, res)],
                "review inventory mismatch",
            )
        require(
            d[label + "-measures"]["component"]["key"] == PROJECT,
            "wrong project for review measures",
        )
        measures = {
            m["metric"]: float(m.get("value", m.get("period", {}).get("value")))
            for m in d[label + "-measures"]["component"]["measures"]
        }
        require(
            all(measures[k] == pct for k in METRICS)
            and measures["security_hotspots"]
            == measures["new_security_hotspots"]
            == (state == "TO_REVIEW")
            and measures["new_lines"] == 645,
            "wrong measures",
        )
        for endpoint, verdict, actual in [
            ("live-gate", current, pct),
            ("analysis-gate", "ERROR", 0),
        ]:
            gate = d[label + "-" + endpoint]["projectStatus"]
            require(
                gate["status"] == verdict
                and not gate["ignoredConditions"]
                and {
                    (c["metricKey"], c["status"], float(c["actualValue"]))
                    for c in gate["conditions"]
                }
                == {(k, verdict, actual) for k in METRICS},
                "wrong current or historical gate",
            )
        result.append(
            {
                "state": state,
                "resolution": res,
                "percent": pct,
                "live_gate": current,
                "analysis_gate": "ERROR",
            }
        )
    for label, state in [
        ("review-line-643", "REVIEWED"),
        ("reopen-line-643", "TO_REVIEW"),
    ]:
        change = d[label]
        require(
            change["endpoint"] == "hotspots/change_status"
            and change["status"] == 204
            and change["parameters"]["hotspot"] == first["key"]
            and change["parameters"]["status"] == state
            and change["parameters"].get("resolution")
            == ("SAFE" if state == "REVIEWED" else None),
            "missing successful review mutation",
        )
    return result


def verify(d):
    verify_configuration(d)
    verify_scope(d)
    return verify_states(d)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "capture",
        type=Path,
        nargs="?",
        default=Path(__file__).with_name("fixtures") / ARCHIVE,
    )
    args = parser.parse_args()
    print(json.dumps(verify(load(args.capture)), indent=2))
