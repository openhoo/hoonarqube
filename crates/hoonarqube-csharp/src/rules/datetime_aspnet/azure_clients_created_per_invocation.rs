use super::support::azure_function_methods;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6420 — per-invocation client construction burns sockets and
/// SDK handshake budget; clients are thread-safe and reusable.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const AZURE_CLIENT_TYPES: [&str; 8] = [
        "BlobContainerClient",
        "BlobClient",
        "BlobServiceClient",
        "QueueClient",
        "TableClient",
        "ServiceBusClient",
        "CosmosClient",
        "SecretClient",
    ];
    azure_function_methods(root, source)
        .into_iter()
        .filter_map(|method| body_of(method))
        .flat_map(|body| collect_kinds(body, &["object_creation_expression"]))
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            AZURE_CLIENT_TYPES.contains(&simple_name(creation_type_text(*creation, source)))
        })
        .map(|creation| {
            issue(
                language,
                "S6420",
                "Create this client once and reuse it across invocations.",
                range_of(creation),
            )
        })
        .collect()
}
