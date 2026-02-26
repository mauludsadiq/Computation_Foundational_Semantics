use std::collections::BTreeMap;
use std::fs;

use asc7::{Asc7Profile, asc7_kernel_cert, normalize_str, verify_terminal};
use asc7::confusables::confusables_kernel_cert;
use collapse_core::{CertChain, CertItem, sem_entropy_bits};
use sembit::{Test, TestFamily, sembit_quotient, tests_hash_hex, quotient_digest_hex, sembit_kernel_cert};
use structural_numbers::{QE, domain_qe_bounded};
use structural_numbers::q_e::domain_digest_hex;

fn t_sign(x: &QE) -> bool { x.num() > 0 }
fn t_is_int(x: &QE) -> bool { x.den() == 1 }
fn t_den_gt_3(x: &QE) -> bool { x.den() > 3 }

#[derive(Clone, Debug)]
struct SpineDigests {
    asc7_hash: String,
    confusables_hash: String,
    domain_digest: String,
    tests_hash: String,
    sembit_hash: String,
    chain_hash: String,
}

fn compute_spine() -> SpineDigests {
    let profile = Asc7Profile::code_safe();
    let asc7_cert = asc7_kernel_cert(&profile);
    let asc7_hash = asc7_cert.kernel_hash_hex();
    let conf_cert = confusables_kernel_cert();
    let confusables_hash = conf_cert.kernel_hash_hex();

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
        &confusables_hash,
        &tests_hash,
        &domain_digest,
        q.size(),
        h,
        &qdig,
    );

    let sembit_hash = sembit_cert.kernel_hash_hex();

    let chain = CertChain::build(vec![
        CertItem { name: "asc7".to_string(), hash_hex: asc7_hash.clone() },
        CertItem { name: "asc7_confusables".to_string(), hash_hex: confusables_hash.clone() },
        CertItem { name: "sembit".to_string(), hash_hex: sembit_hash.clone() },
    ]);

    SpineDigests {
        asc7_hash,
        confusables_hash,
        domain_digest,
        tests_hash,
        sembit_hash,
        chain_hash: chain.chain_hash_hex,
    }
}

fn write_expected_json(d: &SpineDigests) {
    let mut obj = BTreeMap::new();
    obj.insert("confusables_hash", d.confusables_hash.clone());
    obj.insert("asc7_hash", d.asc7_hash.clone());
    obj.insert("domain_digest", d.domain_digest.clone());
    obj.insert("tests_hash", d.tests_hash.clone());
    obj.insert("sembit_hash", d.sembit_hash.clone());
    obj.insert("chain_hash", d.chain_hash.clone());

    let v = serde_json::to_value(obj).unwrap();
    let s = serde_json::to_string_pretty(&v).unwrap();

    fs::create_dir_all("gates").unwrap();
    fs::write("gates/expected.json", s + "\n").unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let do_freeze = args.iter().any(|a| a == "--freeze");

    let profile = Asc7Profile::code_safe();
    let sample = "Hell0 W0r1d (O0I1)";
    let norm = normalize_str(&profile, sample, true).unwrap();
    let is_terminal = verify_terminal(&profile, &norm);

    let d = compute_spine();

    if do_freeze {
        write_expected_json(&d);
        println!("Wrote gates/expected.json");
        println!("chain_hash = sha256:{}", d.chain_hash);
        return;
    }

    println!("=== ASC7 sample ===");
    println!("raw           = {:?}", sample);
    println!("normalized    = {:?}", norm);
    println!("terminal(W*)  = {}", is_terminal);
    println!();

    println!("=== Spine digests ===");
    println!("confusables_hash = sha256:{}", d.confusables_hash);
        println!("asc7_hash     = sha256:{}", d.asc7_hash);
    println!("domain_digest = sha256:{}", d.domain_digest);
    println!("tests_hash    = sha256:{}", d.tests_hash);
    println!("sembit_hash   = sha256:{}", d.sembit_hash);
    println!("chain_hash    = sha256:{}", d.chain_hash);
}
