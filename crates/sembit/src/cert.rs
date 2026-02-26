use std::collections::BTreeMap;

use collapse_core::canon::{Canon, canon_bytes};
use collapse_core::cert::KernelCert;
use collapse_core::digest::{sha256_bytes, sha256_hex};
use collapse_core::quotient::{Quotient, Signature};

use crate::tests::TestFamily;

fn sig_to_canon(sig: &Signature) -> Canon {
    match sig {
        Signature::Bits(bs) => Canon::Arr(bs.iter().map(|b| Canon::Bool(*b)).collect()),
        Signature::Text(s) => Canon::Str(s.clone()),
        Signature::I64(n) => Canon::I64(*n),
        Signature::U64(n) => Canon::U64(*n),
        Signature::PairI64(a, b) => {
            let mut o = BTreeMap::new();
            o.insert("a".to_string(), Canon::I64(*a));
            o.insert("b".to_string(), Canon::I64(*b));
            Canon::Obj(o)
        }
        Signature::Tuple(xs) => Canon::Arr(xs.iter().map(sig_to_canon).collect()),
    }
}

pub fn tests_hash_hex<E>(tf: &TestFamily<E>, impl_tag: &str) -> String {
    let mut arr = Vec::with_capacity(tf.tests.len() + 1);
    for t in &tf.tests {
        arr.push(Canon::Str(t.id_norm.clone()));
    }
    arr.push(Canon::Str(impl_tag.to_string()));
    sha256_hex(sha256_bytes(&canon_bytes(&Canon::Arr(arr))))
}

pub fn quotient_digest_hex<E>(q: &Quotient<E>) -> String {
    let mut arr = Vec::with_capacity(q.classes.len());
    for (sig, members) in q.classes.iter() {
        let mut obj = BTreeMap::new();
        obj.insert("sig".to_string(), sig_to_canon(sig));
        obj.insert("count".to_string(), Canon::U64(members.len() as u64));
        arr.push(Canon::Obj(obj));
    }
    sha256_hex(sha256_bytes(&canon_bytes(&Canon::Arr(arr))))
}

pub fn sembit_kernel_cert(
    asc7_graph_hash_hex: &str,
    confusables_graph_hash_hex: &str,
    tests_hash_hex: &str,
    domain_digest_hex: &str,
    q_classes: usize,
    h_sem_bits: f64,
    quotient_digest_hex: &str,
) -> KernelCert {
    let h_scaled = (h_sem_bits * 1_000_000.0).round() as i64;

    let mut obj = BTreeMap::new();
    obj.insert("asc7_graph_hash".to_string(), Canon::Str(asc7_graph_hash_hex.to_string()));
    obj.insert("confusables_graph_hash".to_string(), Canon::Str(confusables_graph_hash_hex.to_string()));
    obj.insert("tests_hash".to_string(), Canon::Str(tests_hash_hex.to_string()));
    obj.insert("domain_digest".to_string(), Canon::Str(domain_digest_hex.to_string()));
    obj.insert("classes".to_string(), Canon::U64(q_classes as u64));
    obj.insert("h_sem_microbits".to_string(), Canon::I64(h_scaled));
    obj.insert("quotient_digest".to_string(), Canon::Str(quotient_digest_hex.to_string()));

    KernelCert::new("sembit", "1.0.0", Canon::Obj(obj))
}
