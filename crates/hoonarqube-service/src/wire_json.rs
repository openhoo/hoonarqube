use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, de::Error as _};
use serde_json::{Number, Value, value::RawValue};

/// Keep the old `serde_json` parser available for checking the hashes of legacy
/// replays. For storage and readback, reparse floating-point tokens directly
/// with Rust's correctly rounded f64 parser.
pub(crate) fn parse(text: &str) -> serde_json::Result<Value> {
    let mut value = serde_json::from_str(text)?;
    repair_floats(&mut value, text)?;
    Ok(value)
}

fn contains_float(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.is_f64(),
        Value::Array(values) => values.iter().any(contains_float),
        Value::Object(values) => values.values().any(contains_float),
        _ => false,
    }
}

fn repair_floats(value: &mut Value, raw: &str) -> serde_json::Result<()> {
    match value {
        Value::Number(number) if number.is_f64() => {
            let exact: f64 = raw.trim().parse().map_err(serde_json::Error::custom)?;
            *number = Number::from_f64(exact)
                .ok_or_else(|| serde_json::Error::custom("number outside the finite f64 range"))?;
        }
        Value::Array(values) if values.iter().any(contains_float) => {
            let parts: Vec<&RawValue> = serde_json::from_str(raw)?;
            for (value, part) in values.iter_mut().zip(parts) {
                repair_floats(value, part.get())?;
            }
        }
        Value::Object(values) if values.values().any(contains_float) => {
            let parts: BTreeMap<String, &RawValue> = serde_json::from_str(raw)?;
            for (key, value) in values {
                let part = parts.get(key).ok_or_else(|| {
                    serde_json::Error::custom("JSON object field missing from the raw value")
                })?;
                repair_floats(value, part.get())?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    let raw = <&RawValue>::deserialize(deserializer)?;
    parse(raw.get()).map_err(D::Error::custom)
}

pub(crate) fn deserialize_optional<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    let raw = Option::<&RawValue>::deserialize(deserializer)?;
    raw.map(|value| parse(value.get()))
        .transpose()
        .map_err(D::Error::custom)
}
