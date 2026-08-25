// --- python:S5797 — constant conditions

use crate::support::{
    decorator_callee_path, for_each_stmt, is_dunder_all_target, string_value_text,
};
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

pub(crate) fn constant_truth(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(literal) => Some(literal.value),
        Expr::NoneLiteral(_) => Some(false),
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64().map(|value| value != 0),
            ruff_python_ast::Number::Float(value) => Some(*value != 0.0),
            ruff_python_ast::Number::Complex { .. } => None,
        },
        Expr::StringLiteral(literal) => Some(!string_value_text(&literal.value).is_empty()),
        Expr::BoolOp(bool_op) => {
            let operands: Option<Vec<bool>> = bool_op.values.iter().map(constant_truth).collect();
            operands.map(|operands| match bool_op.op {
                ruff_python_ast::BoolOp::And => operands.iter().all(|value| *value),
                ruff_python_ast::BoolOp::Or => operands.iter().any(|value| *value),
            })
        }
        _ => None,
    }
}

pub(crate) const BUILTIN_NAMES: &[&str] = &[
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "exit",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "quit",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
    "__import__",
    "__name__",
    "__file__",
    "__doc__",
    "__spec__",
    "__package__",
    "__loader__",
    "__builtins__",
    "__debug__",
    "__annotations__",
    "__cached__",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "EnvironmentError",
    "Exception",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "NotADirectoryError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "ZeroDivisionError",
];

pub(crate) fn is_builtin_name(name: &str) -> bool {
    BUILTIN_NAMES.contains(&name)
}

pub(crate) fn is_dunder_name(name: &str) -> bool {
    name.len() >= 4 && name.starts_with("__") && name.ends_with("__")
}

pub(crate) fn is_private_name(name: &str) -> bool {
    name.starts_with('_') && !is_dunder_name(name)
}

/// Catalog semantics for the `python:S1481` `regex` parameter: the default
/// value `(_[a-zA-Z0-9_]*|dummy|unused|ignored)` maps to underscore-prefixed
/// names plus the literal alternatives; custom patterns honor top-level `|`
/// alternations with trailing `*` wildcards and literal names.
pub(crate) fn unused_name_matches_pattern(name: &str, pattern: &str) -> bool {
    let trimmed = pattern.strip_prefix('^').unwrap_or(pattern);
    let trimmed = trimmed.strip_suffix('$').unwrap_or(trimmed);
    trimmed.split('|').any(|alternative| {
        let alternative = alternative.trim();
        if alternative == "_[a-zA-Z0-9_]*" {
            return name.starts_with('_');
        }
        if let Some(prefix) = alternative.strip_suffix('*') {
            return name.starts_with(prefix);
        }
        alternative == name
    })
}

pub(crate) fn named_parameters(
    parameters: &ruff_python_ast::Parameters,
) -> Vec<&ruff_python_ast::ParameterWithDefault> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .collect()
}

pub(crate) fn import_binding_name(alias: &ruff_python_ast::Alias) -> Option<String> {
    let name = alias.name.as_str();
    if name == "*" {
        return None;
    }
    Some(match alias.asname.as_deref() {
        Some(asname) => asname.to_string(),
        None => name.split('.').next().unwrap_or(name).to_string(),
    })
}

pub(crate) fn is_tf_function(function: &ruff_python_ast::StmtFunctionDef) -> bool {
    function.decorator_list.iter().any(|decorator| {
        decorator_callee_path(&decorator.expression).as_deref() == Some("tf.function")
    })
}

pub(crate) fn module_all_exports(parsed: &Parsed<ModModule>) -> Vec<(String, TextRange)> {
    let mut exports: Vec<(String, TextRange)> = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (targets, value): (&[Expr], Option<&Expr>) = match stmt {
            Stmt::Assign(assign) => (assign.targets.as_slice(), Some(&assign.value)),
            Stmt::AugAssign(augmented) => (
                std::slice::from_ref(augmented.target.as_ref()),
                Some(augmented.value.as_ref()),
            ),
            _ => return,
        };
        if !targets.iter().any(is_dunder_all_target) {
            return;
        }
        let Some(value) = value else { return };
        let elements: &[Expr] = match value {
            Expr::List(list) => &list.elts,
            Expr::Tuple(tuple) => &tuple.elts,
            _ => return,
        };
        for element in elements {
            if let Expr::StringLiteral(literal) = element {
                exports.push((string_value_text(&literal.value), element.range()));
            }
        }
    });
    exports
}
