# Python S1751: loops that cannot repeat

Community Build 26.11 reports the `while` keyword when every reachable path through the body leaves the loop. An inner loop's `break` ends the inner loop; a `continue` in its `else` suite can continue the enclosing loop. The old detector checked the last statement of a `for` body. It reported nine extra findings in Trio, more-itertools and pytest-xdist and missed all 45 reference locations in the 26.11 control files.

The native analyzer now follows branches and nested loop exits. It leaves uncertain paths through exception handling open. The rule is silent in test files. On `community-26.11-python-core`, supplying `--test-include` explicitly selects the test files; other Python sources use main-file rules even under a directory named `tests`. Omitting the option retains the filename and directory conventions.

## Replay

```sh
cargo build --locked --release -p hoonarqube-cli
python3 tools/oracle/python_single_iteration/replay.py target/release/hoonarqube
python3 tools/oracle/python_empty_alternatives/replay.py target/release/hoonarqube
```

The first command after the build fetches pinned Git objects and checks 394 source files in nine public Python package scopes, plus one real Black formatter fixture. It compares the rule, path, UTF-16 range, message and multiplicity. Five separate control files contain 45 Community 26.11 findings; the 13 findings from one of those files were independently reproduced on 26.9. Black’s fixture is replayed under nine inferred paths and four explicitly classified paths, including cached scans.

The second replay checks S1751 alongside S6323 and S5996 on a separate 16-package cohort with 248 files. The reference recorded no S1751 issue in any of these 25 package scopes. The positive controls are separate from the package results. The selected Python Core profile still declares its incomplete rule coverage; these checks do not qualify all Python rules.
