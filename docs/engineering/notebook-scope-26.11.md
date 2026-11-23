# Jupyter notebook scope in Community 26.11

Hoonarqube includes notebooks in its project inventory. A requested notebook
has no native measurements, so an included notebook makes a project gate
unavailable (exit 2), even when the same directory contains measurable Python
files. Explicit exclusions, ignored files, and vendor/generated scopes keep
their usual meaning. Selecting `--exclude '**/*.ipynb'` evaluates the
remaining files only. The scanner never executes notebook cells.

## Reference measurements

We submitted the unmodified notebook blobs from three pinned public
repositories to SonarQube Community Build 26.11.0.134175, with its built-in
`Sonar way core` notebook profile (230 active rules). The
[fixture](../../tools/oracle/fixtures/notebook-inputs-2611.json) records the
commit, tree, selected file hashes, compute task and analysis IDs, per-file
and project measures, and primary ranges.

| Repository | Notebooks | Reference issues | Files with measured ncloc |
| --- | ---: | ---: | ---: |
| jupyter/nbdime | 4 | 0 | 4 |
| jupyter-widgets/ipywidgets | 9 | 1 | 9 |
| jupyter/nbclassic | 8 | 0 | 7 |

All 21 were indexed as `ipynb`. The physical `lines` metric counted the
original JSON lines, including the terminal empty line in these files. Seven
code-free notebooks reported zero `ncloc`; `Importing Notebooks.ipynb`
contained 18 code cells and had no `ncloc` measure. None of the 21 file
responses contained `duplicated_lines`, although each of the three
notebook-only projects reported zero duplicated lines at project level.
Missing, zero and project-level values are distinct evidence.

Each project also received a separate Community analysis with one real Python
control added to the unmodified notebooks and an assigned gate requiring zero
duplicated lines. Its stored decision passed with actual value 0 in all three
cases. The per-notebook values were unchanged. Hoonarqube currently returns
unavailable for exactly these mixed scopes because it did not measure the
notebooks; reporting a passing zero here would hide this coverage gap.

In `ipywidgets/docs/source/examples/Widget Asynchronous.ipynb`, Community
reported `ipython:S7502` at JSON line 120, zero-based offsets 5–26:
`asyncio.ensure_future`. The import is in a previous code cell. We joined the
code cells as inert text and scanned that projection with the native Python
analyzer. It found `python:S7502` in the same cell but highlighted the full
`asyncio.ensure_future(f())` call, and its project report was incomplete.
The other 20 projections were silent **for this rule**. Ten of the 21
projections produced incomplete Python reports. Concatenating cells is useful
as a diagnostic control; it does not provide an analyzer for original notebook
spans, IPython syntax, or notebook quality gates.

## Inspect a saved notebook

```sh
hoonarqube notebook --json "Widget Asynchronous.ipynb"
```

The command checks a single rule, `ipython:S7502`, for standalone calls to
`asyncio.create_task` or `asyncio.ensure_future`. It uses the native Python
binding resolver, so a saved alias can refer to an import in an earlier code
cell. The saved array order determines the scope. Execution counters, cell
outputs and markdown are not Python source. The scanner never starts a kernel.

A successful inspection returns exit 0, including when it reports a finding.
Its JSON gives the zero-based cell index and a half-open primary range in the
**original JSON** (one-based line, zero-based UTF-16 columns). For the pinned
ipywidgets example above it reports cell 10, line 120, columns 5–26 and the
same rule key and message as Community. Seventeen other originals were inspected
with no finding for this rule. Three returned exit 2: the saved inputs contain
a timing cell magic, a JavaScript cell magic, or unsupported IPython syntax.
They are not counted as matching negative results. These decisions do not
provide `ncloc`, duplication, profile coverage, or gate results.

The parser reads nbformat 4, validates Python kernel/language declarations for
notebooks with code, and parses each saved code cell independently in IPython
mode. Line magics such as `%gui` can be parsed; cell magics (`%%`), conflicting
languages, unsupported syntax and a callee split across JSON strings return
`status: unavailable`, `inspection: null`, exit 2. Source strings and arrays of
strings are both supported. JSON escape sequences and non-BMP Unicode scalars
are mapped from the actual source tokens. Size limits are 4 MiB of original
JSON, 1 MiB of projected code, 4,096 cells and 65,536 source fragments.

## Replay

From the repository root:

```sh
cargo build --locked --release -p hoonarqube-cli
python3 tools/oracle/public_notebook_inputs.py target/release/hoonarqube
```

The replay fetches only the pinned revisions, checks the selected blobs and
uses the native executable. It tests explicit notebook input, a directory
containing an original Python control, and that same directory with notebooks
excluded. It also checks the positive primary range and the 20 silent
controls above. No Jupyter kernel or upstream build is invoked. The recorded
Community analyses are independent reference measurements; replaying them
offline does not create new Community analyses.
