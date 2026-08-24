use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4423 — deprecated SSL/TLS protocol versions invite downgrade
/// attacks; negotiate 'Tls12' or 'Tls13'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let ssl_protocol_accesses = banned_member_accesses(
        root,
        source,
        "SslProtocols",
        &["Ssl2", "Ssl3", "Tls", "Tls10", "Tls11"],
    );
    let security_protocol_accesses =
        banned_member_accesses(root, source, "SecurityProtocolType", &["Ssl3", "Tls"]);
    ssl_protocol_accesses
        .into_iter()
        .chain(security_protocol_accesses)
        .map(|access| {
            issue(
                language,
                "S4423",
                "Negotiate 'Tls12' or 'Tls13' instead of this deprecated protocol.",
                range_of(access),
            )
        })
        .collect()
}
