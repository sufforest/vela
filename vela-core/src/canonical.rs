//! Canonical JSON encoding per Matrix spec (appendices.md:84-130).
//!
//! - Keys lexicographically sorted by Unicode codepoint
//! - No floats — integers only, range [-(2^53)+1, (2^53)-1]
//! - No -0, no exponents, no decimal places
//! - Compact separators: ',' and ':' (no whitespace)
//! - UTF-8 encoded (not \uXXXX escapes for non-ASCII)
//!
//! `write_canonical` substitutes "0" for floats / out-of-range
//! integers as a defensive fallback. Callers ingesting untrusted
//! JSON (federation receive, CS-API send) MUST run
//! `find_invalid_number_path` first and reject with a 400, otherwise
//! the signed event can carry one value through canonical-encode and
//! a different one through the stored JSON.

use serde_json::{Map, Value};

/// Safe-integer bounds matching the Matrix canonical JSON spec
/// (and JavaScript's `Number.MAX_SAFE_INTEGER`).
pub const SAFE_INT_MAX: i64 = (1i64 << 53) - 1;
pub const SAFE_INT_MIN: i64 = -(1i64 << 53) + 1;

fn is_safe_int(i: i64) -> bool {
    (SAFE_INT_MIN..=SAFE_INT_MAX).contains(&i)
}

/// Dotted-path of the first disallowed number (out-of-range integer
/// or any float), or `None` when all numbers are spec-safe. Run at
/// untrusted-JSON ingress before handing the value to
/// `canonical_json`; see the module note for why.
pub fn find_invalid_number_path(value: &Value) -> Option<String> {
    fn walk(v: &Value, path: &str) -> Option<String> {
        match v {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if !is_safe_int(i) {
                        return Some(path.to_string());
                    }
                } else if let Some(u) = n.as_u64() {
                    if u > (1u64 << 53) - 1 {
                        return Some(path.to_string());
                    }
                } else {
                    // Float: spec doesn't permit, full stop.
                    return Some(path.to_string());
                }
                None
            }
            Value::Object(map) => {
                for (k, child) in map {
                    let child_path = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    if let Some(p) = walk(child, &child_path) {
                        return Some(p);
                    }
                }
                None
            }
            Value::Array(arr) => {
                for (i, child) in arr.iter().enumerate() {
                    let child_path = if path.is_empty() {
                        format!("[{i}]")
                    } else {
                        format!("{path}[{i}]")
                    };
                    if let Some(p) = walk(child, &child_path) {
                        return Some(p);
                    }
                }
                None
            }
            _ => None,
        }
    }
    walk(value, "")
}

/// Encode a JSON value as canonical JSON bytes.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf);
    buf
}

/// Encode a JSON object (Map) as canonical JSON bytes.
pub fn canonical_json_object(obj: &Map<String, Value>) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical_object(obj, &mut buf);
    buf
}

fn write_canonical(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(true) => buf.extend_from_slice(b"true"),
        Value::Bool(false) => buf.extend_from_slice(b"false"),
        Value::Number(n) => {
            // Integers only, no exponents, no decimal places
            if let Some(i) = n.as_i64() {
                buf.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                buf.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                // Floats should not appear in Matrix canonical JSON.
                // If we encounter one, convert to integer only if it's a
                // whole number within safe range. Otherwise write as-is.
                if f.fract() == 0.0 && f >= -(2.0_f64.powi(53)) + 1.0 && f <= 2.0_f64.powi(53) - 1.0
                {
                    buf.extend_from_slice((f as i64).to_string().as_bytes());
                } else {
                    // Out of safe integer range or has fractional part — write 0
                    // (this shouldn't happen in valid Matrix JSON)
                    buf.extend_from_slice(b"0");
                }
            }
        }
        Value::String(s) => write_canonical_string(s, buf),
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_canonical(v, buf);
            }
            buf.push(b']');
        }
        Value::Object(obj) => write_canonical_object(obj, buf),
    }
}

fn write_canonical_object(obj: &Map<String, Value>, buf: &mut Vec<u8>) {
    // Keys sorted lexicographically by Unicode codepoint.
    // BTreeMap-backed serde_json::Map is already sorted, but we sort
    // explicitly to be safe regardless of serde_json feature flags.
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();

    buf.push(b'{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        write_canonical_string(key, buf);
        buf.push(b':');
        write_canonical(&obj[*key], buf);
    }
    buf.push(b'}');
}

fn write_canonical_string(s: &str, buf: &mut Vec<u8>) {
    buf.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\x08' => buf.extend_from_slice(b"\\b"),
            '\x0c' => buf.extend_from_slice(b"\\f"),
            '\n' => buf.extend_from_slice(b"\\n"),
            '\r' => buf.extend_from_slice(b"\\r"),
            '\t' => buf.extend_from_slice(b"\\t"),
            c if c < '\x20' => {
                // Control characters below 0x20 must be \uXXXX escaped
                write!(buf, "\\u{:04x}", c as u32).unwrap();
            }
            c => {
                // All other characters (including non-ASCII) are written as UTF-8
                let mut utf8_buf = [0u8; 4];
                buf.extend_from_slice(c.encode_utf8(&mut utf8_buf).as_bytes());
            }
        }
    }
    buf.push(b'"');
}

use std::io::Write as _;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object() {
        assert_eq!(canonical_json(&json!({})), b"{}");
    }

    #[test]
    fn sorted_keys() {
        let v = json!({"b": 2, "a": 1});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn compact_no_whitespace() {
        let v = json!({"key": [1, 2, 3]});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"key":[1,2,3]}"#
        );
    }

    #[test]
    fn utf8_not_escaped() {
        let v = json!({"name": "日本語"});
        let s = String::from_utf8(canonical_json(&v)).unwrap();
        assert!(s.contains("日本語"));
        assert!(!s.contains("\\u"));
    }

    #[test]
    fn control_chars_escaped() {
        let v = json!({"msg": "hello\nworld"});
        let s = String::from_utf8(canonical_json(&v)).unwrap();
        assert_eq!(s, r#"{"msg":"hello\nworld"}"#);
    }

    #[test]
    fn nested_sort() {
        let v = json!({"z": {"b": 1, "a": 2}, "a": 0});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"a":0,"z":{"a":2,"b":1}}"#
        );
    }

    #[test]
    fn integer_not_float() {
        // serde_json parses 42 as integer, 42.0 as float
        let v = json!({"n": 42});
        let s = String::from_utf8(canonical_json(&v)).unwrap();
        assert_eq!(s, r#"{"n":42}"#);
        assert!(!s.contains('.'));
    }

    #[test]
    fn negative_integer() {
        let v = json!({"n": -100});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"n":-100}"#
        );
    }

    #[test]
    fn string_escaping() {
        let v = json!({"s": "quote\"slash\\"});
        let s = String::from_utf8(canonical_json(&v)).unwrap();
        assert_eq!(s, r#"{"s":"quote\"slash\\"}"#);
    }

    #[test]
    fn null_and_bool() {
        let v = json!({"a": null, "b": true, "c": false});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"a":null,"b":true,"c":false}"#
        );
    }

    /// Test against the spec example from appendices.md
    #[test]
    fn spec_example() {
        // The spec gives this example for canonical JSON:
        // Input: {"b":"2","a":"1"}
        // Output: {"a":"1","b":"2"}
        let v: Value = serde_json::from_str(r#"{"b":"2","a":"1"}"#).unwrap();
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"a":"1","b":"2"}"#
        );
    }
}
