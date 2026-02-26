use std::collections::BTreeMap;

/// Minimal canonical JSON-like value for stable hashing.
/// Objects are stored in BTreeMap => keys sorted lexicographically.
/// Arrays preserve order exactly as constructed.
///
/// Note: We deliberately avoid floats in canonical payloads.
/// If you need to store an f64, store it as a scaled integer.
#[derive(Clone, Debug)]
pub enum Canon {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    Str(String),
    Arr(Vec<Canon>),
    Obj(BTreeMap<String, Canon>),
}

pub fn canon_bytes(v: &Canon) -> Vec<u8> {
    let mut out = Vec::new();
    write_canon(&mut out, v);
    out
}

fn write_canon(out: &mut Vec<u8>, v: &Canon) {
    match v {
        Canon::Null => out.extend_from_slice(b"null"),
        Canon::Bool(true) => out.extend_from_slice(b"true"),
        Canon::Bool(false) => out.extend_from_slice(b"false"),
        Canon::I64(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Canon::U64(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Canon::Str(s) => {
            out.push(b'"');
            for &b in s.as_bytes() {
                match b {
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    b'"'  => out.extend_from_slice(b"\\\""),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    b'\t' => out.extend_from_slice(b"\\t"),
                    _ => out.push(b),
                }
            }
            out.push(b'"');
        }
        Canon::Arr(xs) => {
            out.push(b'[');
            for (i, x) in xs.iter().enumerate() {
                if i != 0 { out.push(b','); }
                write_canon(out, x);
            }
            out.push(b']');
        }
        Canon::Obj(map) => {
            out.push(b'{');
            let mut first = true;
            for (k, val) in map.iter() {
                if !first { out.push(b','); }
                first = false;
                write_canon(out, &Canon::Str(k.clone()));
                out.push(b':');
                write_canon(out, val);
            }
            out.push(b'}');
        }
    }
}
