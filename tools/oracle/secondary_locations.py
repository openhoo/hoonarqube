#!/usr/bin/env python3
"""Compare primary messages and supporting flows for selected reference rules.

Distinct flows are unordered by the Sonar server API. Locations within a flow
remain ordered, and multiplicity is preserved at both levels. A flow-free
native finding never equals a reference finding containing supporting evidence.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
from real_project_suite import native_identities, sonar_identities, normalized_path


def span(value):
    return (
        value["start"]["line"],
        value["start"]["column"],
        value["end"]["line"],
        value["end"]["column"],
    )


def sonar_span(value):
    return (
        value["startLine"],
        value["startOffset"],
        value["endLine"],
        value["endOffset"],
    )


def reference_path(component, project_key):
    prefix = project_key + ":"
    if not component.startswith(prefix):
        raise ValueError("supporting location outside reference project")
    return normalized_path(component[len(prefix) :])


def native_signatures(report, rules):
    native_identities(report)  # validate complete supported report
    result = Counter()
    for file in report["files"]:
        path = normalized_path(file["path"])
        for issue in file["issues"]:
            if issue["rule_key"] not in rules:
                continue
            flows = []
            for flow in issue.get("flows", []):
                if not flow.get("locations"):
                    raise ValueError("empty native flow")
                flows.append(
                    tuple(
                        (
                            normalized_path(location.get("path") or path),
                            *span(location["range"]),
                            location["message"],
                        )
                        for location in flow["locations"]
                    )
                )
            result[
                (
                    issue["rule_key"],
                    path,
                    *span(issue["range"]),
                    issue["message"],
                    tuple(sorted(flows)),
                )
            ] += 1
    return result


def reference_signatures(issues, project_key, rules):
    sonar_identities(issues, project_key)
    result = Counter()
    for issue in issues:
        if issue["rule"] not in rules:
            continue
        path = reference_path(issue["component"], project_key)
        flows = []
        for flow in issue.get("flows", []):
            if not flow.get("locations"):
                raise ValueError("empty reference flow")
            flows.append(
                tuple(
                    (
                        reference_path(location["component"], project_key),
                        *sonar_span(location["textRange"]),
                        location["msg"],
                    )
                    for location in flow["locations"]
                )
            )
        result[
            (
                issue["rule"],
                path,
                *sonar_span(issue["textRange"]),
                issue["message"],
                tuple(sorted(flows)),
            )
        ] += 1
    return result


def compare(report, issues, project_key, rules):
    native = native_signatures(report, rules)
    reference = reference_signatures(issues, project_key, rules)

    def count_locations(signatures):
        return sum(
            sum(len(flow) for flow in signature[-1]) * count
            for signature, count in signatures.items()
        )

    return {
        "claim": "selected_rule_primary_message_and_flow_comparison",
        "rules": sorted(rules),
        "native_findings": sum(native.values()),
        "reference_findings": sum(reference.values()),
        "matched_findings": sum((native & reference).values()),
        "native_only": sum((native - reference).values()),
        "reference_only": sum((reference - native).values()),
        "native_supporting_locations": count_locations(native),
        "reference_supporting_locations": count_locations(reference),
        "matched": native == reference,
        "flow_order": "unordered_flows_ordered_locations",
        "differences": [
            {
                "signature": signature,
                "native": native[signature],
                "reference": reference[signature],
            }
            for signature in sorted(native.keys() | reference.keys())
            if native[signature] != reference[signature]
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--rule", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(
        json.loads(args.native.read_text()),
        json.loads(args.reference.read_text()),
        args.project_key,
        set(args.rule),
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print({key: value for key, value in result.items() if key != "differences"})
    return int(not result["matched"])


if __name__ == "__main__":
    raise SystemExit(main())
