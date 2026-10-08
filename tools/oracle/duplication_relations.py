#!/usr/bin/env python3
"""Compare complete native clone relations with captured Sonar per-file APIs.

Each reference relation is repeated in the responses for its origin files.
Deduplicate those representations, retaining occurrence multiplicity inside
each relation. Native duplicate relations remain observable differences.
Sonar reports inclusive line ranges; byte ranges are outside this comparison.
"""

import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath


def part(path, start, end):
    normalized = PurePosixPath(path.replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise ValueError("clone path must stay inside the project")
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError("invalid inclusive clone line range")
    return str(normalized), start, end


def native_relations(report):
    project = report.get("project", {})
    if project.get("complete") is not True:
        raise ValueError("incomplete native analysis")
    result = Counter()
    for group in project["duplications"]:
        occurrences = tuple(
            sorted(
                part(item["path"], item["start_line"], item["end_line"])
                for item in group["occurrences"]
            )
        )
        if len(occurrences) < 2:
            raise ValueError("clone relation requires two occurrences")
        result[occurrences] += 1
    return result


def reference_relations(responses, project_key):
    relations = set()
    for response in responses.values():
        for group in response["duplications"]:
            occurrences = []
            for block in group["blocks"]:
                component = response["files"][block["_ref"]]["key"]
                if not component.startswith(project_key + ":"):
                    raise ValueError("foreign reference clone component")
                size = block["size"]
                if type(size) is not int or size < 1:
                    raise ValueError("invalid reference clone size")
                occurrences.append(
                    part(
                        component[len(project_key) + 1 :],
                        block["from"],
                        block["from"] + size - 1,
                    )
                )
            if len(occurrences) < 2:
                raise ValueError("reference relation requires two occurrences")
            relations.add(tuple(sorted(occurrences)))
    return Counter(dict.fromkeys(relations, 1))


def compare(native, reference, project_key):
    ours = native_relations(native)
    theirs = reference_relations(reference, project_key)
    return {
        "claim": "clone_relation_file_and_inclusive_line_multiset",
        "native_groups": sum(ours.values()),
        "reference_groups": sum(theirs.values()),
        "matched_groups": sum((ours & theirs).values()),
        "native_only": sorted((ours - theirs).items()),
        "reference_only": sorted((theirs - ours).items()),
        "matched": ours == theirs,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(
        json.loads(args.native.read_text()),
        json.loads(args.reference.read_text()),
        args.project_key,
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print({key: value for key, value in result.items() if not isinstance(value, list)})
    return 0 if result["matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
