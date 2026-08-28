// Rule module s6308_opensearch_encryption.
use super::shared::{CdkFile, PropsView, property_value, value_object};
use crate::support::IssueSink;
use crate::support::RuleScope;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

struct DomainSpec {
    fqn: &'static str,
    /// Engine assumed when the configured version names neither engine.
    default_engine: &'static str,
    /// Props key carrying the engine version.
    version_key: &'static str,
    /// Whether the version is a plain string (L1) instead of an
    /// `EngineVersion` member (L2).
    string_version: bool,
}

const DOMAINS: [DomainSpec; 4] = [
    DomainSpec {
        fqn: "aws_cdk_lib.aws_opensearchservice.Domain",
        default_engine: "OpenSearch",
        version_key: "version",
        string_version: false,
    },
    DomainSpec {
        fqn: "aws_cdk_lib.aws_opensearchservice.CfnDomain",
        default_engine: "OpenSearch",
        version_key: "engineVersion",
        string_version: true,
    },
    DomainSpec {
        fqn: "aws_cdk_lib.aws_elasticsearch.Domain",
        default_engine: "Elasticsearch",
        version_key: "version",
        string_version: false,
    },
    DomainSpec {
        fqn: "aws_cdk_lib.aws_elasticsearch.CfnDomain",
        default_engine: "Elasticsearch",
        version_key: "engineVersion",
        string_version: true,
    },
];

/// `S6308`: OpenSearch/Elasticsearch domains should encrypt data at rest.
///
/// Flags missing `encryptionAtRestOptions.enabled` and `enabled: false`,
/// naming the engine resolved from the configured version (falling back to
/// the construct's default engine).
pub(crate) fn check_s6308_opensearch_encryption(
    file: &CdkFile,
    new_expression: &NewExpression<'_>,
    sink: &mut IssueSink,
) {
    let Some(spec) = DOMAINS
        .iter()
        .find(|spec| file.is_cdk(&new_expression.callee, spec.fqn))
    else {
        return;
    };
    let Some(view) = file.props_arg(&new_expression.arguments, 2).view() else {
        return;
    };
    let engine = search_engine(file, &view, spec);
    let omitted = format!(
        "Omitting encryptionAtRest causes encryption of data at rest to be disabled \
         for this {engine} domain. Make sure it is safe here."
    );
    let props_span = match view {
        PropsView::Live(object) => object.span(),
        PropsView::Digested(_) => new_expression.callee.span(),
    };
    let Some(encryption) = property_value(view, "encryptionAtRestOptions") else {
        sink.emit_span(RuleScope::Both, "S6308", &omitted, props_span);
        return;
    };
    let Some(enabled) =
        value_object(encryption).and_then(|object| property_value(object, "enabled"))
    else {
        sink.emit_span(RuleScope::Both, "S6308", &omitted, props_span);
        return;
    };
    if file.value_bool(&enabled) == Some(false) {
        sink.emit_span(
            RuleScope::Both,
            "S6308",
            &format!("Make sure that using unencrypted {engine} domains is safe here."),
            enabled.span(),
        );
    }
}

/// Resolves the engine name from the configured domain version.
fn search_engine(file: &CdkFile, view: &PropsView<'_, '_>, spec: &DomainSpec) -> &'static str {
    let Some(version) = property_value(*view, spec.version_key) else {
        return spec.default_engine;
    };
    let needle = if spec.string_version {
        file.value_str(&version).unwrap_or_default().to_owned()
    } else {
        file.value_fqn(&version).unwrap_or_default()
    };
    let needle = needle.to_lowercase();
    if needle.contains("opensearch") {
        "OpenSearch"
    } else if needle.contains("elasticsearch") {
        "Elasticsearch"
    } else {
        spec.default_engine
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6308_requires_opensearch_encryption_at_rest() {
        let count = |source: &str| -> usize {
            js(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6308"))
                .count()
        };

        // L2 OpenSearch domain without encryptionAtRestOptions.
        assert_eq!(
            count(
                "import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';\n\
             new opensearch.Domain(this, 'D', { version: opensearch.EngineVersion.OPENSEARCH_1_0 });\n"
            ),
            1
        );

        // Explicitly disabled encryption.
        assert_eq!(
            count(
                "import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';\n\
             new opensearch.Domain(this, 'D', {\n\
             \x20 encryptionAtRestOptions: { enabled: false },\n\
             });\n"
            ),
            1
        );

        // L1 CfnDomain with an Elasticsearch engine version string.
        assert_eq!(
            count(
                "import * as elasticsearch from 'aws-cdk-lib/aws-elasticsearch';\n\
             new elasticsearch.CfnDomain(this, 'D', { engineVersion: 'Elasticsearch_7.10' });\n"
            ),
            1
        );

        // Clean: encryption enabled.
        assert_eq!(
            count(
                "import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';\n\
             new opensearch.Domain(this, 'D', {\n\
             \x20 encryptionAtRestOptions: { enabled: true },\n\
             });\n"
            ),
            0
        );
    }
}
