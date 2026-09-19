use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S7941";
const MESSAGE: &str = "Compression modules should be imported from the compression namespace.";
const COMPRESSION_MODULES: [&str; 4] = ["lzma", "bz2", "gzip", "zlib"];

/// python:S7941 — PEP 784 (Python 3.14) gives the compression modules
/// canonical names under the `compression` namespace; the legacy top-level
/// imports keep working but are reported. Scope `MAIN`.
///
/// Mirrors `CompressionModulesFromNamespaceCheck`: only single-name imports
/// are flagged — `import lzma`, `import lzma as l`, and `from lzma import
/// LZMAFile` (including `from .lzma import ...`, whose module name is still a
/// single segment). Deeper paths (`import lzma.foo`, `from a.lzma import x`)
/// and the new namespace itself (`import compression.lzma`, `from
/// compression import lzma`) stay silent. The issue anchors on the imported
/// module name.
pub(crate) fn check_compression_namespace_imports(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for import in &file_ctx.imports {
        match import {
            AnyImport::Plain(stmt) => {
                for alias in &stmt.names {
                    if COMPRESSION_MODULES.contains(&alias.name.as_str()) {
                        issues.push(issue_at(
                            RULE_KEY,
                            MESSAGE,
                            alias.name.range(),
                            index,
                            source,
                        ));
                    }
                }
            }
            AnyImport::From(stmt) => {
                if let Some(module) = &stmt.module
                    && COMPRESSION_MODULES.contains(&module.as_str())
                {
                    issues.push(issue_at(RULE_KEY, MESSAGE, module.range(), index, source));
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7941";

    /// Sonar's own noncompliant example: every legacy single-name import is
    /// flagged; the `compression.*` compliant forms stay silent.
    #[test]
    fn s7941_flags_sonar_examples() {
        let flagged = scan(concat!(
            "from lzma import LZMAFile\n",
            "from bz2 import BZ2File\n",
            "from gzip import GzipFile\n",
            "from zlib import compress\n",
        ));
        assert_eq!(findings(&flagged, KEY).len(), 4);
        let clean = scan(concat!(
            "from compression.lzma import LZMAFile\n",
            "from compression.bz2 import BZ2File\n",
            "from compression.gzip import GzipFile\n",
            "from compression.zlib import compress\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Plain `import` forms, aliases, and the single-name boundary.
    #[test]
    fn s7941_plain_imports_and_boundaries() {
        let report = scan(concat!(
            "import lzma\n",
            "import bz2 as b\n",
            "import gzip, os\n",
            "from .zlib import compress\n",
        ));
        assert_eq!(findings(&report, KEY).len(), 4);
        let clean = scan(concat!(
            "import compression.lzma\n",
            "from compression import lzma\n",
            "import lzmafoo\n",
            "from mylib import lzma\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }
}
