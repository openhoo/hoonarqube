use crate::support::call_source_text;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6275 — EBS volumes encrypted ----------------------------------------

pub(crate) fn check_s6275_ebs_encryption(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let unencrypted_volume = match called_name(&call.func) {
            Some("create_volume") => {
                !has_keyword(&call.arguments, "Encrypted")
                    || keyword_value(&call.arguments, "Encrypted").is_some_and(is_false_literal)
            }
            Some("run_instances") => {
                has_keyword(&call.arguments, "BlockDeviceMappings")
                    && !call_source_text(call, source).contains("Encrypted")
            }
            _ => false,
        };
        if unencrypted_volume {
            issues.push(issue_at(
                "python:S6275",
                "Encrypt this EBS volume at rest.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6275_flags_unencrypted_ebs_volumes() {
        let flagged = concat!(
            "ec2.create_volume(Size=8, AvailabilityZone=\"us-east-1a\")\n",
            "ec2.create_volume(Size=8, Encrypted=False)\n",
            "ec2.run_instances(ImageId=\"ami\", BlockDeviceMappings=[{\"DeviceName\": \"/dev/sda\"}])\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S6275").len(), 3);
        assert!(
            findings(
                &scan(
                    "ec2.create_volume(Size=8, AvailabilityZone=\"us-east-1a\", Encrypted=True)\n"
                ),
                "python:S6275"
            )
            .is_empty()
        );
    }
}
