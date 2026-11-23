use super::*;
use serde_json::json;

fn notebook(cells: &serde_json::Value) -> String {
    json!({"nbformat":4,"metadata":{"kernelspec":{"language":"python"}},"cells":cells}).to_string()
}

#[test]
fn inspects_cross_cell_aliases_and_only_the_saved_callee() {
    let label = "aio.create_task";
    let cells = json!([
        {"cell_type":"markdown","source":label},
        {"cell_type":"code","source":["import asyncio as aio\n","from asyncio import ensure_future as task"]},
        {"cell_type":"code","metadata":{"label":label},"outputs":[{"text":label}],
         "source":"s = '🪶'; aio.create_task(f())\ntask(f())\nkeep = task(f())\ntask = other\ntask(f())"}
    ]);
    let raw = notebook(&cells);
    let report = inspect(&raw).unwrap();
    assert_eq!(
        (report.cells, report.code_cells, report.findings.len()),
        (3, 2, 2)
    );
    let f = &report.findings[0];
    assert_eq!(f.cell_index, 2);
    let offset = raw.find("aio.create_task(f())").unwrap();
    let column = u32::try_from(raw[..offset].encode_utf16().count()).unwrap();
    assert_eq!(
        (f.range.start.line, f.range.start.column, f.range.end.column),
        (1, column, column + 15)
    );
    assert_eq!(
        report.findings[1].range.end.column - report.findings[1].range.start.column,
        4
    );
}
#[test]
fn maps_escaped_surrogates_and_identifier_in_original_crlf_json() {
    let raw = r#"{"nbformat":4,"metadata":{"language_info":{"name":"python"}},"cells":[
{"cell_type":"code","source":"from asyncio import create_task as task"},
{"cell_type":"code","source":["s='\uD83E\udeB6'; \u0074ask(f())","\n"]}
]}"#
    .replace('\n', "\r\n");
    let report = inspect(&raw).unwrap();
    let f = &report.findings[0];
    let line = raw.lines().nth(2).unwrap();
    let off = u32::try_from(line.find("\\u0074ask").unwrap()).unwrap();
    assert_eq!(
        (f.range.start.line, f.range.start.column, f.range.end.column),
        (3, off, off + 9)
    );
}
#[test]
fn rejects_cross_cell_syntax_foreign_kernels_and_unrepresentable_ranges() {
    let cells = |chunks: &[&str]| {
        serde_json::Value::Array(
            chunks
                .iter()
                .map(|s| json!({"cell_type":"code", "source":s}))
                .collect(),
        )
    };
    assert!(inspect(&notebook(&cells(&["if True:", "  import asyncio"]))).is_err());
    assert!(
        inspect(&notebook(&cells(&[
            "%%javascript\nasyncio.create_task(f())"
        ])))
        .is_err()
    );
    let raw = notebook(&cells(&["import asyncio"])).replace("\"python\"", "\"julia\"");
    assert!(inspect(&raw).is_err());
    let raw = notebook(
        &json!([{"cell_type":"code","source":["import asyncio\nasync","io.create_task(f())"]}]),
    );
    assert!(inspect(&raw).unwrap_err().contains("multiple JSON strings"));
}
#[test]
fn distinguishes_ipython_line_magic_and_non_code_from_standalone_tasks() {
    let raw = notebook(&json!([
        {"cell_type":"code","source":["%gui asyncio\n","import asyncio\n","keep = asyncio.ensure_future(f())"]},
        {"cell_type":"raw","source":"asyncio.ensure_future(f())"}]));
    assert!(inspect(&raw).unwrap().findings.is_empty());
}

#[test]
fn refuses_incomplete_schema_and_input_budgets() {
    let code =
        json!([{"cell_type":"code","source":"x=1", "metadata":{"vscode":{"languageId":"r"}}}]);
    assert!(
        inspect(&notebook(&code))
            .unwrap_err()
            .contains("non-Python cell")
    );
    let missing = notebook(&json!([{"cell_type":"code","source":"x=1"}]))
        .replace("{\"kernelspec\":{\"language\":\"python\"}}", "{}");
    assert!(inspect(&missing).unwrap_err().contains("language"));
    assert!(inspect(r#"{"nbformat":4,"metadata":{},"cells":[],"cells":[]}"#).is_err());
    assert!(
        inspect(&" ".repeat(MAX_JSON_BYTES + 1))
            .unwrap_err()
            .contains("4 MiB")
    );
    let cells = vec![json!({"cell_type":"markdown", "source":""}); MAX_CELLS + 1];
    assert!(
        inspect(&notebook(&json!(cells)))
            .unwrap_err()
            .contains("4096")
    );
    let cells = json!([{"cell_type":"code","source":vec!["";MAX_FRAGMENTS+1]}]);
    assert!(inspect(&notebook(&cells)).unwrap_err().contains("65536"));
}

#[test]
fn uses_source_order_and_ignores_stored_outputs_and_execution_counts() {
    let cells = json!([
        {"cell_type":"code", "source":"aio.create_task(f())", "execution_count":4},
        {"cell_type":"code", "source":"import asyncio as aio", "execution_count":1},
        {"cell_type":"code", "source":"aio.create_task(f())\naio = local\naio.create_task(f())",
         "outputs":[{"text":"aio.create_task(f())"}], "execution_count":0}
    ]);
    let raw = notebook(&cells);
    let report = inspect(&raw).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].cell_index, 2);
}
