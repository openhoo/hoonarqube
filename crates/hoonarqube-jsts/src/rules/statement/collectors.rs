// Residual rule machinery for 'statement' (extracted from lib.rs).

pub(crate) fn is_error_type_name(name: &str) -> bool {
    name == "Error" || name.ends_with("Error")
}
