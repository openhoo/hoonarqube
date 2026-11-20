//! Conversions from the native report into external finding formats.
//! Each consumer owns its path, location, rule metadata and identity conventions.

pub(crate) mod gitlab;
pub(crate) mod sarif;
pub(crate) mod sonar;

/// Lexically resolve a report path inside the checkout. Export also supports
/// in-memory reports, so this intentionally does not touch the filesystem.
fn with_checkout_relative<T>(
    path: &std::path::Path,
    checkout_root: &std::path::Path,
    context: &str,
    encode: impl FnOnce(&std::path::Path) -> Result<T, String>,
) -> Result<T, String> {
    let root = normalize_path(checkout_root)
        .ok_or_else(|| "checkout root is not a valid normalized path".to_owned())?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let absolute = normalize_path(&absolute)
        .ok_or_else(|| format!("{context} is outside checkout root: {}", path.display()))?;
    let relative = absolute
        .strip_prefix(&root)
        .map_err(|_| format!("{context} is outside checkout root: {}", path.display()))?;
    encode(relative)
}

fn normalize_path(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    Some(normalized)
}
