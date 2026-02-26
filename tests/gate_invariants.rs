use asc7::{Asc7Profile, asc7_kernel_cert, normalize_str, verify_terminal};
use asc7::confusables::confusables_kernel_cert;
use sembit::{Test, TestFamily, sembit_quotient, tests_hash_hex, quotient_digest_hex, sembit_kernel_cert};
use collapse_core::{sem_entropy_bits, CertChain, CertItem};
use structural_numbers::{QE, domain_qe_bounded};
use structural_numbers::q_e::domain_digest_hex;

fn t_sign(x: &QE) -> bool { x.num() > 0 }
fn t_is_int(x: &QE) -> bool { x.den() == 1 }
fn t_den_gt_3(x: &QE) -> bool { x.den() > 3 }

#[test]
fn gate_asc7_idempotent_and_terminal() {
    let p = Asc7Profile::code_safe();
    let s = "Hell0 W0r1d (O0I1)";
    let s1 = normalize_str(&p, s, true).unwrap();
    let s2 = normalize_str(&p, &s1, true).unwrap();
    assert_eq!(s1, s2);
    assert!(verify_terminal(&p, &s1));
}

#[test]
fn gate_spine_chain_contains_asc7_hash() {
    let profile = Asc7Profile::code_safe();
    let asc7_cert = asc7_kernel_cert(&profile);
    let asc7_hash = asc7_cert.kernel_hash_hex();
    let conf_cert = confusables_kernel_cert();
    let conf_hash = conf_cert.kernel_hash_hex();

    let domain: Vec<QE> = domain_qe_bounded(10, 10);
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
        &asc7_hash, &conf_hash, &tests_hash, &domain_digest, q.size(), h, &qdig
    );

    let chain = CertChain::build(vec![
        CertItem { name: "asc7".to_string(), hash_hex: asc7_hash.clone() },
        CertItem { name: "asc7_confusables".to_string(), hash_hex: conf_hash.clone() },
        CertItem { name: "sembit".to_string(), hash_hex: sembit_cert.kernel_hash_hex() },
    ]);

    // The chain hash must depend on asc7 hash; change asc7 hash => chain changes.
    let mut chain2 = chain.clone();
    chain2.items[0].hash_hex = "deadbeef".to_string();
    chain2.chain_hash_hex = collapse_core::cert_chain_hash(&chain2.items);
    assert_ne!(chain.chain_hash_hex, chain2.chain_hash_hex);
    assert!(chain.items[0].hash_hex.len() == 64);
}
