import argparse
import json
import os
from pathlib import Path

from parity import write_json_atomic
from public_corpus_capture import DockerSonar, bootstrap, utc

parser = argparse.ArgumentParser(
    description="Capture effective local Sonar way parameters after the pilot"
)
parser.add_argument("--state", type=Path, required=True)
args = parser.parse_args()
state = args.state.resolve()
raw = state / "profiles"
os.umask(0o077)
raw.mkdir(exist_ok=True)
sonar = DockerSonar(bootstrap(state) + ":")
profiles = json.loads((state / "pilot/requests/profiles.json").read_text())["profiles"]
summary = {}
for profile in profiles:
    language = profile["language"]
    rules = sonar.pages(
        "/api/rules/search",
        {"qprofile": profile["key"], "activation": "true", "f": "actives,params"},
        "rules",
        raw,
        "effective-" + language,
    )
    if len(rules) != profile["activeRuleCount"]:
        raise ValueError("active rule count disagrees with profile")
    metadata = {
        r["key"]: r
        for page in (state / "pilot/requests").glob(f"active-{language}-page-*.json")
        for r in json.loads(page.read_text())["rules"]
    }
    if metadata.keys() != {r["key"] for r in rules}:
        raise ValueError("rule keys changed since the pilot capture")
    activations = {}
    for p in sorted(raw.glob(f"effective-{language}-page-*.json")):
        data = json.loads(p.read_text())
        if not data.get("actives", {}).keys() == {r["key"] for r in data["rules"]}:
            raise ValueError("missing rule activation")
        for key, variants in data.get("actives", {}).items():
            match = [v for v in variants if v["qProfile"] == profile["key"]]
            if len(match) != 1:
                raise ValueError("ambiguous rule activation")
            activations[key] = {v["key"]: v["value"] for v in match[0]["params"]}
    summary[language] = {
        "name": profile["name"],
        "builtin": profile["isBuiltIn"],
        "default": profile["isDefault"],
        "profile_key": profile["key"],
        "rules": {
            r["key"]: {
                "type": metadata[r["key"]]["type"],
                "scope": metadata[r["key"]]["scope"],
                "parameters": activations[r["key"]],
            }
            for r in rules
        },
    }
write_json_atomic(
    raw / "effective.json", {"captured_at_utc": utc(), "profiles": summary}
)
print(
    "Captured",
    len(summary),
    "effective profiles",
    sum(len(v["rules"]) for v in summary.values()),
    "active rule entries",
    flush=True,
)
