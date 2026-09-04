#!/usr/bin/env python3
"""Generate deterministic CLI performance fixtures in a new directory."""

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
    ruby = "".join(f"def compute{i}(value)\n  value + {i}\nend\n" for i in range(30))
    python = "".join(f"x{j} = 1; y{j} = 2 # TODO\n" for j in range(40))
    workloads = [
        ("tiny-jsts", 4096, ".js", "export const value = 1;\n"),
        ("rust-arrays", 1, ".rs", arrays),
        ("ruby-metrics", 64, ".rb", ruby),
        ("report-heavy", 400, ".py", python),
    ]
    for name, count, extension, source in workloads:
        directory = root / name
        directory.mkdir()
        for index in range(count):
            (directory / f"file{index:04d}{extension}").write_text(source)

    controls = root / "rust-controls"
    controls.mkdir()
    cases = itertools.product(
        ["a", "mut", "let", "_foo"],
        [
            "let NAME = value;",
            "let mut NAME = value;",
            "let let NAME;",
            "let other = value;",
            "",
        ],
        ["NAME[2]", "éNAME[2]", "NAME[２]", "NAME2[2]"],
    )
    for index, (name, shadow, access) in enumerate(cases):
        source = (
            f"fn main() {{ let {name} = [1]; consume!({access}); "
            f"{shadow} consume!({access}); }}\n"
        )
        (controls / f"control{index:03d}.rs").write_text(source.replace("NAME", name))


def main():
    """Read the output directory and generate every workload."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    generate(parser.parse_args().directory)


if __name__ == "__main__":
    main()
