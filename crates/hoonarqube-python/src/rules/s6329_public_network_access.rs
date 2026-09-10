use super::s6275_ebs_encryption::Ec2Bindings;
use crate::engine::file_context::{AnyImport, FileContext};
use crate::support::collect_target_names;
use crate::support::{is_true_literal, issue_at, keyword_range, keyword_value};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextSize};

fn root_module_imported(imports: &[AnyImport<'_>], local: &str) -> bool {
    imports.iter().any(|import| match import {
        AnyImport::Plain(import) => import.names.iter().any(|alias| {
            let name = alias.name.as_str();
            (name == "aws_cdk" || name.starts_with("aws_cdk."))
                && alias
                    .asname
                    .as_deref()
                    .unwrap_or_else(|| name.split('.').next().unwrap_or(""))
                    == local
        }),
        AnyImport::From(_) => false,
    })
}

fn service_module_imported(imports: &[AnyImport<'_>], service: &str, local: &str) -> bool {
    let dotted = format!("aws_cdk.{service}");
    imports.iter().any(|import| match import {
        AnyImport::Plain(import) => import.names.iter().any(|alias| {
            alias.name.as_str() == dotted
                && alias
                    .asname
                    .as_deref()
                    .is_some_and(|asname| asname == local)
        }),
        AnyImport::From(import) => {
            import
                .module
                .as_ref()
                .is_some_and(|module| module.as_str() == "aws_cdk")
                && import.names.iter().any(|alias| {
                    (alias.name.as_str() == service || alias.name.as_str() == "*")
                        && alias.asname.as_deref().unwrap_or(service) == local
                })
        }
    })
}

fn constructor_imported(
    imports: &[AnyImport<'_>],
    service: &str,
    constructor: &str,
    local: &str,
) -> bool {
    let module_name = format!("aws_cdk.{service}");
    imports.iter().any(|import| {
        let AnyImport::From(import) = import else {
            return false;
        };
        import
            .module
            .as_ref()
            .is_some_and(|module| module.as_str() == module_name)
            && import.names.iter().any(|alias| {
                alias.name.as_str() == constructor
                    && alias.asname.as_deref().unwrap_or(constructor) == local
            })
    })
}

fn rebound_before(file_ctx: &FileContext<'_>, name: &str, at: TextSize) -> bool {
    for stmt in &file_ctx.stmts {
        let mut names = Vec::new();
        let activation = match stmt {
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    collect_target_names(target, &mut names);
                }
                Some(assign.value.end())
            }
            Stmt::AnnAssign(assign) => {
                collect_target_names(&assign.target, &mut names);
                assign.value.as_deref().map(Ranged::end)
            }
            Stmt::AugAssign(assign) => {
                collect_target_names(&assign.target, &mut names);
                Some(assign.value.end())
            }
            Stmt::For(for_stmt) => {
                collect_target_names(&for_stmt.target, &mut names);
                Some(for_stmt.iter.end())
            }
            Stmt::FunctionDef(function) => {
                names.push(function.name.to_string());
                Some(
                    function
                        .body
                        .first()
                        .map_or_else(|| stmt.range().end(), Ranged::start),
                )
            }
            Stmt::ClassDef(class) => {
                names.push(class.name.to_string());
                Some(stmt.range().end())
            }
            _ => None,
        };
        if activation.is_some_and(|activation| activation <= at)
            && names.iter().any(|candidate| candidate == name)
        {
            return true;
        }
    }
    false
}

fn is_legacy_public_resource_constructor(
    function: &Expr,
    file_ctx: &FileContext<'_>,
    at: TextSize,
) -> bool {
    let service = match function {
        Expr::Name(name) => {
            for (service, constructor) in [
                ("aws_rds", "CfnDBInstance"),
                ("aws_dms", "CfnReplicationInstance"),
            ] {
                if constructor_imported(&file_ctx.imports, service, constructor, name.id.as_str())
                    && !rebound_before(file_ctx, name.id.as_str(), at)
                {
                    return true;
                }
            }
            return false;
        }
        Expr::Attribute(attribute) => match attribute.attr.as_str() {
            "CfnDBInstance" => "aws_rds",
            "CfnReplicationInstance" => "aws_dms",
            _ => return false,
        },
        _ => return false,
    };
    let Expr::Attribute(attribute) = function else {
        return false;
    };
    match attribute.value.as_ref() {
        Expr::Name(name) => {
            service_module_imported(&file_ctx.imports, service, name.id.as_str())
                && !rebound_before(file_ctx, name.id.as_str(), at)
        }
        Expr::Attribute(module) => {
            module.attr.as_str() == service
                && matches!(
                    module.value.as_ref(),
                    Expr::Name(root)
                        if root_module_imported(&file_ctx.imports, root.id.as_str())
                            && !rebound_before(file_ctx, root.id.as_str(), at)
                )
        }
        _ => false,
    }
}

fn check_public_subnet_instance(
    call: &ruff_python_ast::ExprCall,
    bindings: Option<&Ec2Bindings>,
    at: TextSize,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) -> bool {
    let Some(bindings) = bindings else {
        return false;
    };
    if !bindings.is_instance_constructor(&call.func, at) {
        return false;
    }
    let Some(subnets) = keyword_value(&call.arguments, "vpc_subnets") else {
        return true;
    };
    let Expr::Call(selection) = subnets else {
        return true;
    };
    if !bindings.is_subnet_selection_constructor(&selection.func, at) {
        return true;
    }
    let Some(subnet_type) = keyword_value(&selection.arguments, "subnet_type") else {
        return true;
    };
    if !bindings.is_public_subnet_type(subnet_type, at) {
        return true;
    }
    issues.push(issue_at(
        "python:S6329",
        "Make sure allowing public network access is safe here.",
        keyword_range(&call.arguments, "vpc_subnets").unwrap_or_else(|| subnets.range()),
        index,
        source,
    ));
    true
}
pub(crate) fn check_s6329_public_network_access(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let bindings = file_ctx
        .has_aws_cdk_import
        .then(|| Ec2Bindings::collect(file_ctx));
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let at = call.range().start();
        if check_public_subnet_instance(call, bindings.as_ref(), at, index, source, &mut issues) {
            continue;
        }
        if is_legacy_public_resource_constructor(&call.func, file_ctx, at)
            && keyword_value(&call.arguments, "publicly_accessible").is_some_and(is_true_literal)
        {
            issues.push(issue_at(
                "python:S6329",
                "Make sure allowing public network access is safe here.",
                keyword_range(&call.arguments, "publicly_accessible")
                    .unwrap_or_else(|| call.range()),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6329_flags_only_cdk_instances_in_public_subnets() {
        let attack = concat!(
            "from aws_cdk import aws_ec2 as ec2\n",
            "instance = ec2.Instance(\n",
            "    self, \"instance\", vpc=vpc,\n",
            "    vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),\n",
            ")\n",
        );
        assert_eq!(findings(&scan(attack), "python:S6329").len(), 1);
        let safe = concat!(
            "from aws_cdk import aws_ec2 as ec2\n",
            "instance = ec2.Instance(\n",
            "    self, \"instance\", vpc=vpc,\n",
            "    vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),\n",
            ")\n",
        );
        assert!(findings(&scan(safe), "python:S6329").is_empty());
        let unknown = concat!(
            "from aws_cdk import aws_ec2 as ec2\n",
            "def make_instance(subnet_type):\n",
            "    return ec2.Instance(self, \"instance\", vpc_subnets=ec2.SubnetSelection(subnet_type=subnet_type))\n",
        );
        assert!(findings(&scan(unknown), "python:S6329").is_empty());
    }

    #[test]
    fn s6329_requires_trusted_ec2_aliases_and_rebinding() {
        let source = concat!(
            "from aws_cdk.aws_ec2 import Instance as Ec2Instance, SubnetSelection, SubnetType\n",
            "Ec2Instance(self, \"real\", vpc_subnets=SubnetSelection(subnet_type=SubnetType.PUBLIC))\n",
            "Ec2Instance = LocalInstance\n",
            "Ec2Instance(self, \"local\", vpc_subnets=SubnetSelection(subnet_type=SubnetType.PUBLIC))\n",
            "import aws_cdk_fake.aws_ec2 as fake_ec2\n",
            "fake_ec2.Instance(self, \"lookalike\", vpc_subnets=fake_ec2.SubnetSelection(subnet_type=fake_ec2.SubnetType.PUBLIC))\n",
        );
        assert_eq!(findings(&scan(source), "python:S6329").len(), 1);
    }

    #[test]
    fn s6329_preserves_legacy_cdk_resource_check() {
        let source = concat!(
            "from aws_cdk import aws_rds as rds\n",
            "rds.CfnDBInstance(scope, \"database\", publicly_accessible=True)\n",
            "rds.CfnDBInstance(scope, \"private\", publicly_accessible=False)\n",
        );
        assert_eq!(findings(&scan(source), "python:S6329").len(), 1);
    }
}
