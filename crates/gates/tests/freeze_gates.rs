use std::collections::BTreeMap;
use std::fs;

use asc7::{Asc7Profile, asc7_kernel_cert, normalize_str};
use asc7::confusables::confusables_kernel_cert;
use collapse_core::{CertChain, CertItem, sem_entropy_bits};
use sembit::{Test, TestFamily, sembit_quotient, tests_hash_hex, quotient_digest_hex, sembit_kernel_cert};
use structural_numbers::{QE, domain_qe_bounded};
use structural_numbers::q_e::domain_digest_hex;

fn t_sign(x: &QE) -> bool { x.num() > 0 }
fn t_is_int(x: &QE) -> bool { x.den() == 1 }
fn t_den_gt_3(x: &QE) -> bool { x.den() > 3 }

fn compute_spine() -> BTreeMap<String, String> {
    let profile = Asc7Profile::code_safe();
    let asc7_cert = asc7_kernel_cert(&profile);
    let asc7_hash = asc7_cert.kernel_hash_hex();
    let conf_cert = confusables_kernel_cert();
    let conf_hash = conf_cert.kernel_hash_hex();

    let domain: Vec<QE> = domain_qe_bounded(20, 20);
    let domain_digest = domain_digest_hex(&domain);

    let id1 = normalize_str(&profile, "sign", true).unwrap();
    let id2 = normalize_str(&profile, "is_int", true).unwrap();
    let id3 = normalize_str(&profile, "den>3", true).unwrap();

    let tf = TestFamily::new(vec![
        Test { id_norm: id1, f: t_sign },
        Test { id_norm: id2, f: t_is_int },
        Test { id_norm: id3, f: t_den_gt_3 },
    ]);

    let tests_hash = tests_hash_hex(&tf, "impl:static_v1");
    let q = sembit_quotient(&domain, &tf);
    let h = sem_entropy_bits(q.size());
    let qdig = quotient_digest_hex(&q);

    let sembit_cert = sembit_kernel_cert(
        &asc7_hash,
        &conf_hash,
        &tests_hash,
        &domain_digest,
        q.size(),
        h,
        &qdig,
    );

    let sembit_hash = sembit_cert.kernel_hash_hex();

    let chain = CertChain::build(vec![
        CertItem { name: "asc7".to_string(), hash_hex: asc7_hash.clone() },
        CertItem { name: "asc7_confusables".to_string(), hash_hex: conf_hash.clone() },
        CertItem { name: "sembit".to_string(), hash_hex: sembit_hash.clone() },
    ]);

    let mut m = BTreeMap::new();
    m.insert("confusables_hash".to_string(), conf_hash);
    m.insert("asc7_hash".to_string(), asc7_hash);
    m.insert("domain_digest".to_string(), domain_digest);
    m.insert("tests_hash".to_string(), tests_hash);
    m.insert("sembit_hash".to_string(), sembit_hash);
    m.insert("chain_hash".to_string(), chain.chain_hash_hex);
    m
}

#[test]
fn gate_freeze_expected_digests() {
    let path = "../../gates/expected.json";
    let raw = fs::read_to_string(path).unwrap_or_else(|_| {
        panic!("Missing {path}. Generate it with: cargo run -p collapse_spine_demo -- --freeze");
    });

    let expected: BTreeMap<String, String> = serde_json::from_str(&raw).unwrap();
    let got = compute_spine();

    for k in ["confusables_hash", "asc7_hash", "domain_digest", "tests_hash", "sembit_hash", "chain_hash"] {
        let e = expected.get(k).unwrap_or_else(|| panic!("expected.json missing key: {k}"));
        let g = got.get(k).unwrap();
        assert_eq!(g, e, "freeze gate mismatch for key={k}");
    }
}
