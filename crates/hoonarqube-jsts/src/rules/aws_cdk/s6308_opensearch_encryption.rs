// Rule module s6308_opensearch_encryption.
use super::shared::{CdkFile, PropsArg, PropsView, ValueView, property_value, value_object};
use crate::support::IssueSink;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::{Expression, NewExpression, UnaryOperator};
use oxc_span::GetSpan;

struct DomainSpec {
    fqn: &'static str,
    /// Engine assumed when the configured version names neither engine.
    default_engine: &'static str,
    /// Props key carrying the encryption configuration.
    encryption_key: &'static str,
    /// Props key carrying the engine version.
    version_key: &'static str,
    /// Whether the version is a plain string (L1) instead of an
    /// `EngineVersion`/`ElasticsearchVersion` member (L2).
    string_version: bool,
}

const DOMAINS: [DomainSpec; 4] = [
    DomainSpec {
        fqn: "aws_cdk_lib.aws_opensearchservice.Domain",
        default_engine: "OpenSearch",
        encryption_key: "encryptionAtRest",
        version_key: "version",
        string_version: false,
    },
    DomainSpec {
        fqn: "aws_cdk_lib.aws_opensearchservice.CfnDomain",
        default_engine: "OpenSearch",
        encryption_key: "encryptionAtRestOptions",
        version_key: "engineVersion",
        string_version: true,
    },
    DomainSpec {
        fqn: "aws_cdk_lib.aws_elasticsearch.Domain",
        default_engine: "Elasticsearch",
        encryption_key: "encryptionAtRest",
        version_key: "version",
        string_version: false,
    },
    DomainSpec {
        fqn: "aws_cdk_lib.aws_elasticsearch.CfnDomain",
        default_engine: "Elasticsearch",
        encryption_key: "encryptionAtRestOptions",
        version_key: "elasticsearchVersion",
        string_version: true,
    },
];

/// `S6308`: OpenSearch/Elasticsearch domains should encrypt data at rest.
///
/// Flags missing encryption configuration `enabled` and `enabled: false`,
/// naming the engine resolved from the configured version (falling back to
/// the construct's default engine). L2 domains use `encryptionAtRest`, while
/// L1 `CfnDomain` resources use `encryptionAtRestOptions`.
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
    let props = file.props_arg(&new_expression.arguments, 2);
    let props_is_void = new_expression
        .arguments
        .get(2)
        .and_then(|argument| argument.as_expression())
        .is_some_and(is_void_expression);
    if matches!(props, PropsArg::Absent) || props_is_void {
        sink.emit_span(
            RuleScope::Both,
            "S6308",
            &format!(
                "Omitting {} causes encryption of data at rest to be disabled \
                 for this {} domain. Make sure it is safe here.",
                spec.encryption_key, spec.default_engine
            ),
            new_expression.callee.span(),
        );
        return;
    }
    let Some(view) = props.view() else {
        return;
    };
    let engine = search_engine(file, &view, spec);
    let omitted = format!(
        "Omitting {} causes encryption of data at rest to be disabled \
         for this {engine} domain. Make sure it is safe here.",
        spec.encryption_key
    );
    let props_span = match view {
        PropsView::Live(object) => object.span(),
        PropsView::Digested(_) => new_expression.callee.span(),
    };
    let Some(encryption) = property_value(view, spec.encryption_key) else {
        sink.emit_span(RuleScope::Both, "S6308", &omitted, props_span);
        return;
    };
    let Some(encryption_props) = value_object(encryption) else {
        if is_provably_undefined_value(&encryption) {
            sink.emit_span(RuleScope::Both, "S6308", &omitted, encryption.span());
        }
        return;
    };
    let Some(enabled) = property_value(encryption_props, "enabled") else {
        sink.emit_span(RuleScope::Both, "S6308", &omitted, encryption.span());
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

fn is_void_expression(expression: &Expression<'_>) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::Void
    )
}

fn is_provably_undefined_value(view: &ValueView<'_, '_>) -> bool {
    match view {
        ValueView::Live(expression) => is_void_expression(expression),
        ValueView::Digested(_) => false,
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

    fn count(source: &str) -> usize {
        js(source)
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S6308"))
            .count()
    }

    #[test]
    fn s6308_distinguishes_l2_and_l1_encryption_properties() {
        // The L2 Domain API uses `encryptionAtRest`.
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.Domain(this, 'D', {\n\
             \x20 version: opensearchservice.EngineVersion.OPENSEARCH_1_3,\n\
             \x20 encryptionAtRest: { enabled: true },\n\
             });\n"
            ),
            0
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.Domain(this, 'D', {\n\
             \x20 version: opensearchservice.EngineVersion.OPENSEARCH_2_5,\n\
             \x20 encryptionAtRest: { enabled: true },\n\
             });\n"
            ),
            0
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.Domain(this, 'D', {\n\
             \x20 version: opensearchservice.EngineVersion.OPENSEARCH_2_5,\n\
             \x20 encryptionAtRest: { enabled: false },\n\
             });\n"
            ),
            1
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.Domain(this, 'D', {\n\
             \x20 version: opensearchservice.EngineVersion.OPENSEARCH_1_3,\n\
             });\n"
            ),
            1
        );

        // The L1 CfnDomain API keeps the CloudFormation property name.
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.CfnDomain(this, 'D', {\n\
             \x20 engineVersion: 'OpenSearch_1.3',\n\
             \x20 encryptionAtRestOptions: { enabled: true },\n\
             });\n"
            ),
            0
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.CfnDomain(this, 'D', {\n\
             \x20 engineVersion: 'OpenSearch_1.3',\n\
             \x20 encryptionAtRest: { enabled: true },\n\
             });\n"
            ),
            1
        );

        // A local binding named `undefined` is unknown, not an omitted props object.
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             function f() {\n\
             \x20 const undefined = { encryptionAtRest: { enabled: true } };\n\
             \x20 new opensearchservice.Domain(this, 'D', undefined);\n\
             }\n"
            ),
            0
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             function f() {\n\
             \x20 const undefined = true;\n\
             \x20 new opensearchservice.Domain(this, 'D', {\n\
             \x20\x20 encryptionAtRest: { enabled: undefined },\n\
             \x20 });\n\
             }\n"
            ),
            0
        );

        // A syntactically void value is provably omitted, unlike an opaque identifier.
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.CfnDomain(this, 'D', void 0);\n"
            ),
            1
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice as opensearchservice } from 'aws-cdk-lib';\n\
             new opensearchservice.CfnDomain(this, 'D', {\n\
             \x20 engineVersion: 'OpenSearch_1.3',\n\
             \x20 encryptionAtRestOptions: void 0,\n\
             });\n"
            ),
            1
        );
    }

    #[test]
    fn s6308_supports_typescript_l2_near_shapes() {
        let count = |source: &str| -> usize {
            ts(source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S6308"))
                .count()
        };

        assert_eq!(
            count(
                "import { aws_opensearchservice } from 'aws-cdk-lib';\n\
             new aws_opensearchservice.Domain(this, 'Domain', {\n\
             \x20 version: aws_opensearchservice.EngineVersion.OPENSEARCH_2_3,\n\
             \x20 encryptionAtRest: { enabled: true },\n\
             });\n"
            ),
            0
        );
        assert_eq!(
            count(
                "import { aws_opensearchservice } from 'aws-cdk-lib';\n\
             new aws_opensearchservice.Domain(this, 'Domain', {\n\
             \x20 version: aws_opensearchservice.EngineVersion.OPENSEARCH_2_5,\n\
             \x20 encryptionAtRest: { enabled: true },\n\
             });\n"
            ),
            0
        );
    }
}
