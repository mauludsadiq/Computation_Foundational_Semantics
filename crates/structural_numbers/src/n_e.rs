use crate::q_e::canon_domain_digest_hex_u64;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NE(pub u64);

impl NE {
    pub fn new(n: u64) -> Self { Self(n) }
    pub fn value(&self) -> u64 { self.0 }
}

/// Domain: {0,1,2,...,nmax}
pub fn domain_ne(nmax: u64) -> Vec<NE> {
    let mut v = Vec::new();
    for n in 0..=nmax {
        v.push(NE(n));
    }
    v
}

/// Digest of NE domain (stable, canonical).
pub fn domain_digest_hex_ne(domain: &[NE]) -> String {
    let raw: Vec<u64> = domain.iter().map(|x| x.0).collect();
    canon_domain_digest_hex_u64(&raw)
}

/// Human-legible view: map index -> value
pub fn domain_view_ne(domain: &[NE]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("kind".to_string(), "N_E".to_string());
    m.insert("size".to_string(), format!("{}", domain.len()));
    if let Some(first) = domain.first() {
        m.insert("first".to_string(), format!("{}", first.0));
    }
    if let Some(last) = domain.last() {
        m.insert("last".to_string(), format!("{}", last.0));
    }
    m
}
