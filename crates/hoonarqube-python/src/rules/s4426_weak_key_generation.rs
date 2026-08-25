use crate::support::dotted_name;
use crate::support::for_each_attr_load;
use crate::support::for_each_call;
use crate::support::int_literal_value;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s4426_weak_key_generation(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const KEY_GENERATORS: [&str; 2] = ["RSA", "DSA"];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let small_key = is_call_method(call, "generate")
            && dotted_name(&call.func).is_some_and(|p| {
                p.rsplit_once('.')
                    .is_some_and(|(head, _)| KEY_GENERATORS.contains(&head))
            })
            && call
                .arguments
                .args
                .first()
                .and_then(int_literal_value)
                .is_some_and(|bits| bits < STRONG_MINIMUM_KEY_BITS);
        if small_key {
            issues.push(issue_at(
                "python:S4426",
                "Use a key size of 2048 bits or larger for this key generation.",
                call.range(),
                index,
                source,
            ));
        }
    });
    for curve in WEAK_ELLIPTIC_CURVES {
        for_each_attr_load(parsed.syntax().body.as_slice(), curve, |attr| {
            issues.push(issue_at(
                "python:S4426",
                "Replace this weak elliptic curve with a stronger one.",
                attr.range(),
                index,
                source,
            ));
        });
    }
    issues
}

// --- migrated from support/mod.rs (S4426) ---
// --- python:S4426 — cryptographic key generation based on strong parameters --

const STRONG_MINIMUM_KEY_BITS: i64 = 2048;

const WEAK_ELLIPTIC_CURVES: [&str; 2] = ["SECP192R1", "SECP224R1"];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4426_flags_weak_key_generation_parameters() {
        let flagged = concat!(
            "RSA.generate(1024)\n",
            "DSA.generate(1024)\n",
            "ec.generate_private_key(ec.SECP192R1())\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4426").len(), 3);
        let clean = concat!(
            "RSA.generate(4096)\n",
            "ec.generate_private_key(ec.SECP384R1())\n"
        );
        assert!(findings(&scan(clean), "python:S4426").is_empty());
    }
}
