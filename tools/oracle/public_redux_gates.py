"""Check project policy, history and hotspot review on two immutable Redux revisions."""

import argparse
import json
import tempfile
from pathlib import Path

from community_combined_coverage import git
from community_hotspot_replay import BASE, HEAD, replay
from project_gate_policy_replay import run


def compare(binaries, repository, work):
    checkout = work / "base"
    checkout.mkdir()
    git(checkout, "init", "-q")
    git(
        checkout,
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=2",
        "--update-shallow",
        repository,
        BASE,
        HEAD,
    )
    git(checkout, "checkout", "--quiet", "--detach", BASE)
    candidate = work / "head"
    git(checkout, "worktree", "add", "--quiet", "--detach", str(candidate), HEAD)
    args = (
        binaries / "hoonarqube",
        binaries / "hoonarqube-service",
        checkout,
        candidate,
    )
    reviews, policies = work / "reviews", work / "policies"
    reviews.mkdir()
    policies.mkdir()
    return {
        "reviews": replay(*args, reviews, mapped=True),
        "assigned": run(*args, policies),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path)
    parser.add_argument("--repository", default="https://github.com/reduxjs/redux.git")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as work:
        print(
            json.dumps(
                compare(args.binaries.resolve(), args.repository, Path(work).resolve()),
                indent=2,
            )
        )
