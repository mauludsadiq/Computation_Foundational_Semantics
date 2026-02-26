use crate::q_e::canon_domain_digest_hex_i64;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ZE(pub i64);

impl ZE {
    pub fn new(z: i64) -> Self { Self(z) }
    pub fn value(&self) -> i64 { self.0 }
}

/// Domain: {-zmax,...,0,...,+zmax}
pub fn domain_ze(zmax: i64) -> Vec<ZE> {
    let mut v = Vec::new();
    let mut z = -zmax;
    while z <= zmax {
        v.push(ZE(z));
        z += 1;
    }
    v
}

/// Digest of ZE domain (stable, canonical).
pub fn domain_digest_hex_ze(domain: &[ZE]) -> String {
    let raw: Vec<i64> = domain.iter().map(|x| x.0).collect();
    canon_domain_digest_hex_i64(&raw)
}

/// Human-legible view: map index -> value
pub fn domain_view_ze(domain: &[ZE]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("kind".to_string(), "Z_E".to_string());
    m.insert("size".to_string(), format!("{}", domain.len()));
    if let Some(first) = domain.first() {
        m.insert("first".to_string(), format!("{}", first.0));
    }
    if let Some(last) = domain.last() {
        m.insert("last".to_string(), format!("{}", last.0));
    }
    m
}
