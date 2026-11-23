"""Read two real pre-binding scanner decisions after a process upgrade and logical restore."""

import copy
import tempfile
from functools import partial
from pathlib import Path

from community_custom_hotspot import BASE, BASE_ID, CONTROL, HEAD, SOURCE, require
from community_hotspot_replay import check_gate, reject, request, service_clients
from community_scm_period import descriptor, run_case
from smoke_cli_service import running_service


def upgrade(previous, current, apache, yjs, data, work):
    from community_custom_hotspot_native import (
        UNBOUND,
        YFILE,
        YHEAD,
        clone_at,
        review,
        yjs_case,
    )

    work.mkdir()
    root = work / "apache"
    clone_at(root, apache, BASE, HEAD, [SOURCE, CONTROL])
    selected = descriptor(data["head-gate"]["projectStatus"]["period"], BASE_ID, BASE)
    scanner = previous / "hoonarqube"
    code, java, _ = run_case(
        scanner, root, work, [str(Path(SOURCE).parent)], BASE, HEAD, selected, [UNBOUND]
    )
    require(
        code == 0,
        "the pre-upgrade scanner does not exhibit the old empty-hotspot behavior",
    )
    js = yjs_case(scanner, yjs, work / "yjs", condition=UNBOUND)
    original = work / "old-database"
    original.mkdir()
    start, ingest, roles = service_clients(previous / "hoonarqube-service", original)
    reader = roles["admin"]
    metric = UNBOUND["metric"]
    with start() as port:
        a = ingest(port, java, "main", HEAD)["id"]
        y = ingest(port, js, "main", YHEAD)["id"]
        route = f"/smoke/analyses/{y}"
        entries = request(port, reader, route + "/findings")["findings"]
        (hit,) = [
            f
            for f in entries
            if f["kind"] == "hotspot"
            and f["path"] == YFILE
            and f["range"]["start"]["line"] == 35
        ]
        review(port, roles["reviewer"], y, hit["identity"], "safe", 0)
        check_gate(request(port, reader, route + "/gate"), 100, "pass", metric)
        backup = request(port, reader, "/smoke/export")

    def check_history(port):
        for i, actual, status in [(a, None, "no_value"), (y, 0, "fail")]:
            route = f"/smoke/analyses/{i}"
            check_gate(
                request(port, reader, route)["analysis"]["gate"], actual, status, metric
            )
            check_gate(
                request(port, reader, route + "/gate"), None, "unavailable", metric
            )
        matches = request(port, reader, f"/smoke/analyses/{y}/findings")["findings"]
        (row,) = [f for f in matches if f["identity"] == hit["identity"]]
        require(
            row["review"]["state"] == "safe" and row["review"]["version"] == 1,
            "lost historical review",
        )
        # An archived decision is allowed only on the explicit restore route.
        reject(
            partial(
                request,
                port,
                reader,
                "/smoke/analyses",
                {
                    "schema_version": 1,
                    "branch": "stale",
                    "commit": HEAD,
                    "analyzed_at": "2026-11-23T00:00:00Z",
                    "report": java,
                },
            ),
            409,
        )

    with running_service(current, original, reader) as port:
        check_history(port)
    with (
        tempfile.TemporaryDirectory(dir=work) as tmp,
        running_service(current, Path(tmp), reader) as port,
    ):
        tampered = copy.deepcopy(backup)
        tampered["analyses"][0]["report"]["assessment"]["gate"]["conditions"][0][
            "actual"
        ] = 100
        reject(partial(request, port, reader, "/smoke/restore", tampered), 409)
        request(port, reader, "/smoke/restore", backup)
        check_history(port)
    return {
        "historical_claims": ["no_value", "fail"],
        "live": "unavailable",
        "review_version": 1,
        "restored": True,
    }
