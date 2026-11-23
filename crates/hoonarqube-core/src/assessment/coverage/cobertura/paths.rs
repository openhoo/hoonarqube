use std::collections::BTreeSet;
use std::path::Path;

use super::super::{
    SourceIndex, is_absolute_like, is_windows_absolute, normalize_report_path, path_key,
};

/// Resolves against the scanner's inventory without reading report-supplied
/// directories. A foreign absolute <source> is only metadata: a CI report
/// can still supply an exact checkout-relative filename.
pub(in super::super) struct PathIndex<'a> {
    index: &'a SourceIndex<'a>,
    roots: BTreeSet<String>,
}

impl<'a> PathIndex<'a> {
    pub(in super::super) fn new(index: &'a SourceIndex<'a>, source_roots: &[String]) -> Self {
        let roots = source_roots
            .iter()
            .filter_map(|root| normalize(index, root))
            .filter(|root| !root.is_empty())
            .collect();
        Self { index, roots }
    }

    pub(in super::super) fn resolve(
        &self,
        filename: &str,
        diagnostics: &mut Vec<String>,
    ) -> Option<&'a str> {
        let Some(path) = normalize(self.index, filename).filter(|path| !path.is_empty()) else {
            diagnostics.push(format!(
                "Cobertura path '{filename}' is outside the explicit coverage root"
            ));
            return None;
        };
        let mut candidates = BTreeSet::new();
        self.add_candidates(&path, &mut candidates);
        if !is_absolute_like(&filename.replace('\\', "/")) {
            for root in &self.roots {
                self.add_candidates(&format!("{root}/{path}"), &mut candidates);
                if candidates.len() > 1 {
                    break;
                }
            }
        }
        match candidates.len() {
            1 => candidates.first().copied(),
            0 => {
                diagnostics.push(format!(
                    "unknown analyzed Cobertura source path '{filename}'"
                ));
                None
            }
            _ => {
                diagnostics.push(format!(
                    "ambiguous analyzed Cobertura source path '{filename}'"
                ));
                None
            }
        }
    }

    fn add_candidates(&self, path: &str, candidates: &mut BTreeSet<&'a str>) {
        if self.index.root_windows {
            if let Some(paths) = self.index.folded.get(&path_key(path)) {
                candidates.extend(paths.iter().map(String::as_str));
            }
        } else if let Some(entry) = self.index.entries.get(path) {
            candidates.insert(entry.path.as_str());
        }
    }
}

fn normalize(index: &SourceIndex<'_>, path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    if is_absolute_like(&path)
        && (!is_absolute_like(&index.root) || is_windows_absolute(&path) != index.root_windows)
    {
        return None;
    }
    normalize_report_path(&index.root, index.root_windows, Path::new(&path))
}
