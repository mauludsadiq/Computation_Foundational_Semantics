use num_integer::gcd;
use std::cmp::Ordering;
use std::collections::BTreeMap;

use collapse_core::canon::{Canon, canon_bytes};
use collapse_core::digest::{sha256_bytes, sha256_hex};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QE {
    num: i64,
    den: i64, // invariant: den > 0
}

impl QE {
    pub fn new(mut n: i64, mut d: i64) -> Self {
        if d == 0 {
            panic!("QE::new: zero denominator");
        }
        if d < 0 {
            n = -n;
            d = -d;
        }
        let g = gcd(n.abs(), d);
        let n = n / g;
        let d = d / g;
        Self { num: n, den: d }
    }

    pub fn num(&self) -> i64 { self.num }
    pub fn den(&self) -> i64 { self.den }
}

impl Ord for QE {
    fn cmp(&self, other: &Self) -> Ordering {
        let lhs = self.num as i128 * other.den as i128;
        let rhs = other.num as i128 * self.den as i128;
        lhs.cmp(&rhs)
            .then_with(|| self.den.cmp(&other.den))
            .then_with(|| self.num.cmp(&other.num))
    }
}

impl PartialOrd for QE {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn canon_domain_digest_hex_u64(domain: &[u64]) -> String {
    let arr: Vec<Canon> = domain.iter().map(|x| Canon::U64(*x)).collect();
    sha256_hex(sha256_bytes(&canon_bytes(&Canon::Arr(arr))))
}

pub fn canon_domain_digest_hex_i64(domain: &[i64]) -> String {
    let arr: Vec<Canon> = domain.iter().map(|x| Canon::I64(*x)).collect();
    sha256_hex(sha256_bytes(&canon_bytes(&Canon::Arr(arr))))
}

/// Canonical domain digest: sha256(canon([{num,den}, ...])).
/// Caller should supply deterministic order; our enumerators sort+dedup.
pub fn domain_digest_hex(domain: &[QE]) -> String {
    let mut arr = Vec::with_capacity(domain.len());
    for q in domain {
        let mut obj = BTreeMap::new();
        obj.insert("num".to_string(), Canon::I64(q.num()));
        obj.insert("den".to_string(), Canon::I64(q.den()));
        arr.push(Canon::Obj(obj));
    }
    sha256_hex(sha256_bytes(&canon_bytes(&Canon::Arr(arr))))
}
