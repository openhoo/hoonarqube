# Python current-contract qualification, 2026-10-08

The complete active Python rule inventory was replayed against the frozen
Requests and Werkzeug sources analyzed by the SonarQube 26.9 container.
Every source file hash and project commit was verified before native analysis.

| Project | Active rules compared | Native findings | Reference findings | Exact findings |
| --- | ---: | ---: | ---: | ---: |
| Requests | 398 | 77 | 77 | 77 |
| Werkzeug | 398 | 230 | 230 | 230 |

Exact detector comparison includes the rule key, report path, both range
endpoints, issue message, and duplicate multiplicity. Explicit Python project
contexts rooted at `.` and `src` preserve the same results. The sibling cognitive
qualification additionally verifies 902 ordered secondary locations for its
55 complexity findings.

Receipts:

- `python-full-active-qualification-20261008.json`
- `python-nominal-qualification-20261008.json`
- `python-cognitive-protocol-qualification-20261008.json`
- `python-cli-namespace-qualification-20261008.json`

## Quickfix contracts

`python_quickfix_current_contracts.py` executes 16 current contracts covering
seven rules from the historical failed quickfix replay. It records analysis,
projection, apply, readback, regression guards, and runtime evidence. Its result
retains the selected historical application records verbatim. The portable
qualification retains the seven historical failures alongside the separate
current results.

| Rule | Qualified contract |
| --- | --- |
| S1720 | Strict-profile docstring application; reference-profile inactive control |
| S1854 | Function-local positive; module, sentinel, and effectful RHS controls |
| S4144 | Three-line implementation positive; one-line implementation control |
| S6553 | Proven Django model field positive; top-level call control |
| S5719 | Empty method receiver application with the valuable-body S2325 gate |
| S6545 | Builtin generic projection with the exempt typing-import S1128 gate |
| S3923 | Truth-preserving native projection and refusal when S2201 increases |

For S3923, actual Python execution checks truth, false, and exception behavior.
The native projection preserves the original effects and exceptions. The
historical upstream projection drops truth testing; all three runtime controls
show the behavioral difference. Refused applies preserve the original bytes.
This boundary is recorded explicitly as a source-different contract.

Run the contracts with an actual built CLI and the retained historical result:

```sh
python3 tools/oracle/python_quickfix_current_contracts.py \
  --binary /absolute/path/to/hoonarqube \
  --historical-result /absolute/path/to/historical/result.json \
  --output /absolute/path/to/new/qualification
```

`fix --profile strict` uses the selected profile during planning and every
verification pass. The default remains the reference profile. The CLI regression
suite verifies strict docstring application and default-profile refusal.

The detector receipt covers the two source inventories and their captured
active profiles. Rule parameters, other projects, hotspots, and metrics have
separate qualification evidence.
