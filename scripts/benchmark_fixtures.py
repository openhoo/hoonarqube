#!/usr/bin/env python3
"""Generate deterministic CLI performance fixtures in a new directory.

Every file is owned by this invocation and refuses to overwrite an existing
directory. Larger repeated workloads vary identifiers/literals per file so
project duplication remains complete under the CLI's normal bounded budget.
"""

import argparse
import itertools
from pathlib import Path


def generate(root):
    """Create workloads without overwriting an existing fixture directory."""
    root.mkdir(parents=True, exist_ok=False)
    arrays = (
        "fn main() {\n"
        + "".join(
            f"let values{i} = [1, 2]; consume!(values{i}[2]);\n" for i in range(300)
        )
        + "}\n"
    )

    def ruby_source(file_index):
        return "".join(
            f"def compute{i}(value)\n  value + {file_index * 30 + i}\nend\n"
            for i in range(30)
        )

    def python_source(file_index):
        return "".join(
            f"x{file_index}_{j} = 1; y{file_index}_{j} = 2 # TODO\n" for j in range(40)
        )

    workloads = [
        (
            "tiny-jsts",
            4096,
            ".js",
            lambda index: f"export const value{index} = 1;\n",
        ),
        ("rust-arrays", 1, ".rs", lambda _index: arrays),
        ("ruby-metrics", 64, ".rb", ruby_source),
        ("report-heavy", 400, ".py", python_source),
    ]
    for name, count, extension, source_for in workloads:
        directory = root / name
        directory.mkdir()
        for index in range(count):
            (directory / f"file{index:04d}{extension}").write_text(
                source_for(index),
                encoding="utf-8",
            )

    controls = root / "rust-controls"
    controls.mkdir()
    cases = itertools.product(
        ["a", "mut_value", "let_value", "_foo"],
        [
            "let shadow_NAME = value;",
            "let mut shadow_NAME = value;",
            "let alias_NAME = value;",
            "let other_NAME = value;",
            "",
        ],
        ["NAME[2]", "éNAME[2]", "NAME[3]", "NAME2[2]"],
    )
    for index, (name, shadow, access) in enumerate(cases):
        source = (
            f"fn main() {{ let {name} = [1]; consume!({access}); "
            f"{shadow} consume!({access}); }}\n"
        )
        (controls / f"control{index:03d}.rs").write_text(
            source.replace("NAME", name),
            encoding="utf-8",
        )


def main():
    """Read the output directory and generate every workload."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    generate(parser.parse_args().directory)


if __name__ == "__main__":
    main()
