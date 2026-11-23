"""Replay six explicitly synthetic layout controls from the live Community comparison."""

import hashlib
import json
import subprocess
from pathlib import Path

from public_coverage_gate_replay import check

CAPTURE = Path(__file__).with_name("fixtures") / "notebook-layouts-2611.json"


def input_bytes(name):
    def code(index, source):
        return {
            "cell_type": "code",
            "id": str(index),
            "metadata": {},
            "execution_count": None,
            "outputs": [],
            "source": source,
        }

    cases = {
        "array-pretty": (['x = "🦉"\n', "task(f())"], 1, False),
        "array-compact": (['x = "🦉"; task(f())'], None, False),
        "surrogates": (['x = "🦉"; task(f())'], 1, True),
        "single-source": ('x = "🦉"; task(f())', 1, False),
        "escaped-name": (['x = "🦉"; task(f())'], 1, True),
        "retained": (["keep = task(f())"], 1, False),
    }
    src, indent, ascii_only = cases[name]
    imports = "from asyncio import create_task as task\n"
    doc = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python", "version": "3.12.0"},
        },
        "cells": [
            code(0, imports if name == "single-source" else [imports]),
            code(1, src),
        ],
    }
    raw = json.dumps(doc, indent=indent, ensure_ascii=ascii_only)
    if name == "escaped-name":
        raw = raw.replace("task(f())", r"\u0074ask(f())")
    return (raw + "\n").encode()


def replay(binary, work):
    capture = json.loads(CAPTURE.read_bytes())
    check(
        capture["reference_build"] == "26.11.0.134175"
        and capture["profile"] == "Sonar way core"
        and capture["rule"] == "ipython:S7502",
        "wrong notebook layout reference",
    )
    different = set()
    for filename, row in capture["results"].items():
        path = work / filename
        raw = input_bytes(path.stem)
        check(
            hashlib.sha256(raw).hexdigest() == row["sha256"], f"{filename}: input drift"
        )
        path.write_bytes(raw)
        run = subprocess.run(
            [binary, "notebook", "--json", path],
            check=True,
            capture_output=True,
            timeout=30,
        )
        hits = json.loads(run.stdout)["inspection"]["findings"]
        check(len(hits) == int(row["native"] is not None), f"{filename}: finding count")
        if not hits:
            check(
                row["reference"] is None and row["equal"],
                f"{filename}: missing reference",
            )
            continue
        span = hits[0]["range"]
        check(
            span == row["native"] and hits[0]["rule_key"] == capture["rule"],
            f"{filename}: native range",
        )
        start, end = span["start"], span["end"]
        line = raw.decode().splitlines()[start["line"] - 1].encode("utf-16-le")
        highlighted = line[2 * start["column"] : 2 * end["column"]].decode("utf-16-le")
        check(
            json.loads('"' + highlighted + '"') == "task",
            f"{filename}: wrong raw token",
        )
        ref = row["reference"]
        same = (start["line"], start["column"], end["line"], end["column"]) == (
            ref["startLine"],
            ref["startOffset"],
            ref["endLine"],
            ref["endOffset"],
        )
        check(same == row["equal"], f"{filename}: unexpected reference comparison")
        if not same:
            different.add(filename)
    check(
        len(capture["results"]) == 6
        and different == {"escaped-name.ipynb", "surrogates.ipynb"},
        "layout controls changed",
    )
