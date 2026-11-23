"""Verify the two assigned Java hotspot reference populations and frozen core rule types."""

import gzip
import json
from pathlib import Path

from community_custom_hotspot import (
    BASE,
    CONTROL,
    CONTROL_HASH,
    HEAD,
    METRICS,
    SOURCE,
    SOURCE_HASH,
    require,
)

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures/hotspot-populations-2611.json"


def verify_capture(path=FIXTURE):
    evidence = json.loads(path.read_bytes())
    ref = evidence["reference"]
    require(
        ref["version"] == "26.11.0.134175"
        and ref["server"]
        == "sonarqube@sha256:7b2296713a92b8ea0dd7a083a25faadc59376c9a1e6daf2744a89711c54ea1ba"
        and ref["scanner"].endswith(
            "@sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9"
        )
        and ref["template"] == "java:S4011"
        and ref["rule_parameters"]
        == {
            "className": "java.util.Random",
            "argumentTypes": None,
            "allOverloads": "true",
        }
        and ref["rule"] == "java:hqrngpopulation261120261123",
        "unrecognized Community capture",
    )
    root = HERE.parents[1]
    table = (
        (root / "catalog/reference/community-26.11-core-hotspot-types.tsv")
        .read_text()
        .splitlines()
    )
    expected = ["\t".join((ref["version"], "Sonar way core", "complete-active-set"))]
    fast = json.loads(
        gzip.decompress(
            (HERE / "fixtures/fastapi-default-gate-26.11.json.gz").read_bytes()
        )
    )
    for language, expected_count in (("java", 263), ("python", 232)):
        profile = evidence["core"][language]
        active = profile["rules"]
        metadata = profile["profile"]
        require(
            metadata["isBuiltIn"]
            and metadata["isDefault"]
            and metadata["name"] == "Sonar way core"
            and metadata["language"] == {"python": "py", "java": "java"}[language]
            and profile["version"] == ref["version"],
            "wrong core profile",
        )
        require(
            len(active) == metadata["activeRuleCount"] == expected_count
            and set(active.values()) == {"CODE_SMELL", "BUG", "VULNERABILITY"},
            "incomplete or unexpected core population",
        )
        if language == "python":
            require(
                fast["profile"]["key"] == metadata["key"]
                and active.keys() == fast["active_rules"].keys(),
                "different FastAPI core profile",
            )
        expected += ["\t".join((language, key, active[key])) for key in sorted(active)]
    require(table == expected, "product rule-type map differs from measured profiles")
    projects = ref["profiles"]
    require(
        set(projects) == {"default", "custom"}
        and projects["default"]["policy"]["gate"]
        == projects["custom"]["policy"]["gate"],
        "different gate",
    )
    ids = set()
    for kind, row in projects.items():
        p = row["policy"]
        require(
            row["indexed_files"] == {SOURCE: "java", CONTROL: "java"}
            and {(c["metric"], c["op"], c["error"]) for c in p["conditions"]}
            == {(m, "LT", "100") for m in METRICS},
            "wrong indexed source or assigned gate",
        )
        require(
            p["profile"]["isBuiltIn"]
            == p["profile"]["isDefault"]
            == (kind == "default"),
            "wrong profile assignment",
        )
        require(
            p["hotspot_rules"]
            == ([[ref["rule"], "SECURITY_HOTSPOT"]] if kind == "custom" else [])
            and p["profile"]["activeRuleCount"] == (1 if kind == "custom" else 263),
            "wrong typed population",
        )
        if kind == "default":
            require(
                p["profile"]["key"] == evidence["core"]["java"]["profile"]["key"],
                "wrong Java core key",
            )
        for label, rev, hashes in (
            ("base", BASE, {CONTROL: CONTROL_HASH}),
            ("candidate", HEAD, {CONTROL: CONTROL_HASH, SOURCE: SOURCE_HASH}),
        ):
            scan = row["scans"][label]
            require(
                scan["revision"] == rev and scan["sha256"] == hashes,
                "different public files",
            )
            ids.update((scan["task"], scan["analysis"]))
        initial = row["initial"]
        for phase, expected_percent in (
            [("initial", 0), ("safe", 100), ("reopened", 0)]
            if kind == "custom"
            else [("initial", None)]
        ):
            state = row[phase]
            require(
                state["historical"]
                == row["scans"]["candidate"]["gate"]
                == initial["historical"],
                "historical analysis changed",
            )
            for g in (state["live"], state["historical"]):
                require(
                    not g["ignoredConditions"]
                    and g["period"]["mode"] == "SPECIFIC_ANALYSIS"
                    and g["period"]["parameter"] == row["scans"]["base"]["analysis"],
                    "wrong SCM period or ignored gate",
                )
            cond = state["live"]["conditions"]
            if expected_percent is None:
                require(
                    state["live"]["status"] == "OK"
                    and not cond
                    and state["overall"] == state["new"] == [],
                    "empty population did not omit the condition",
                )
            else:
                status = "OK" if expected_percent == 100 else "ERROR"
                require(
                    state["live"]["status"] == status
                    and {
                        (
                            c["metricKey"],
                            c["comparator"],
                            c["errorThreshold"],
                            float(c["actualValue"]),
                            c["status"],
                        )
                        for c in cond
                    }
                    == {(m, "LT", "100", expected_percent, status) for m in METRICS},
                    "wrong live review decision",
                )
                (h,) = state["new"]
                require(
                    state["overall"] == [h]
                    and h["key"] == initial["new"][0]["key"]
                    and h["component"] == row["project"] + ":" + SOURCE
                    and h["line"] == 643
                    and h["ruleKey"] == ref["rule"]
                    and (h["status"], h.get("resolution"))
                    == (
                        ("REVIEWED", "SAFE")
                        if expected_percent
                        else ("TO_REVIEW", None)
                    ),
                    "different reviewed hotspot",
                )
    require(len(ids) == 8, "reused reference task or analysis")
    return ref
