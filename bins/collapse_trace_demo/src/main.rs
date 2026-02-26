use std::collections::BTreeMap;
use std::path::Path;

use asc7::{Asc7Profile, asc7_kernel_cert, normalize_str};
use asc7::confusables::confusables_kernel_cert;

use collapse_core::canon::canon_bytes;
use collapse_core::cert::KernelCert;
use collapse_core::quotient::{Quotient, Signature};
use collapse_core::{CertChain, CertItem, sem_entropy_bits};

use sembit::{Test, TestFamily, tests_hash_hex, quotient_digest_hex, sembit_kernel_cert};

use structural_numbers::{QE, domain_qe_bounded};
use structural_numbers::{domain_ne, domain_digest_hex_ne, domain_view_ne};
use structural_numbers::{domain_ze, domain_digest_hex_ze, domain_view_ze};
use structural_numbers::q_e::domain_digest_hex;

use traceutil::{Trace, run_stamp};

fn trace_kernel(trace: &mut Trace, label: &str, cert: &KernelCert) -> String {
    trace.section(&format!("KERNEL: {label}"));
    let bytes = canon_bytes(&cert.payload);
    trace.bytes_hex_preview("canonical_bytes", &bytes);
    let h = cert.kernel_hash_hex();
    trace.kv("sha256(canonical_bytes)", &h);
    trace.kv("kernel_hash_hex", &h);
    h
}

fn t_sign(x: &QE) -> bool { x.num() > 0 }
fn t_is_int(x: &QE) -> bool { x.den() == 1 }
fn t_den_gt_3(x: &QE) -> bool { x.den() > 3 }

fn main() {
    let stamp = run_stamp();
    let out_dir = Path::new("out");

    let mut tr_struct = Trace::new(out_dir, &stamp, "structural").unwrap();
    let mut tr_sembit = Trace::new(out_dir, &stamp, "sembits").unwrap();
    let mut tr_asc7 = Trace::new(out_dir, &stamp, "asc7").unwrap();

    tr_struct.banner("Structural Numbers trace (QE, N_E, Z_E)");
    tr_sembit.banner("SemBits trace (tests → signatures → quotient → cert)");
    tr_asc7.banner("ASC7 trace (profile → normalize → confusables kernel)");

    tr_asc7.section("ASC7 PROFILE");
    let profile = Asc7Profile::code_safe();
    tr_asc7.kv("profile", "Asc7Profile::code_safe()");

    tr_asc7.section("ASC7 KERNEL CERT");
    let asc7_cert = asc7_kernel_cert(&profile);
    let asc7_hash = trace_kernel(&mut tr_asc7, "asc7", &asc7_cert);

    tr_asc7.section("CONFUSABLES KERNEL CERT");
    let conf_cert = confusables_kernel_cert();
    let conf_hash = trace_kernel(&mut tr_asc7, "asc7_confusables", &conf_cert);

    tr_asc7.section("NORMALIZE EXAMPLES (WITH PROFILE)");
    for raw in ["sign", "is_int", "den>3", "A", "a", "O", "o"] {
        let norm = normalize_str(&profile, raw, true).unwrap();
        tr_asc7.kv(&format!("normalize({raw})"), &norm);
    }

    tr_struct.section("QE DOMAIN: CONSTRUCTION");
    let domain_qe: Vec<QE> = domain_qe_bounded(20, 20);
    tr_struct.kv("domain_qe_bounded(nmax=20, dmax=20)", &format!("size={}", domain_qe.len()));
    if let Some(first) = domain_qe.first() {
        tr_struct.kv("first", &format!("{}/{}", first.num(), first.den()));
    }
    if let Some(last) = domain_qe.last() {
        tr_struct.kv("last", &format!("{}/{}", last.num(), last.den()));
    }

    tr_struct.section("QE DOMAIN DIGEST");
    let qe_digest = domain_digest_hex(&domain_qe);
    tr_struct.kv("domain_digest_hex(QE)", &qe_digest);

    tr_struct.section("N_E DOMAIN: CONSTRUCTION");
    let ne = domain_ne(40);
    let ne_view = domain_view_ne(&ne);
    for (k, v) in ne_view {
        tr_struct.kv(&format!("N_E.{k}"), &v);
    }
    let ne_digest = domain_digest_hex_ne(&ne);
    tr_struct.kv("domain_digest_hex(N_E)", &ne_digest);

    tr_struct.section("Z_E DOMAIN: CONSTRUCTION");
    let ze = domain_ze(20);
    let ze_view = domain_view_ze(&ze);
    for (k, v) in ze_view {
        tr_struct.kv(&format!("Z_E.{k}"), &v);
    }
    let ze_digest = domain_digest_hex_ze(&ze);
    tr_struct.kv("domain_digest_hex(Z_E)", &ze_digest);

    tr_sembit.section("TEST FAMILY: NON-BINARY VIA TUPLED SIGNATURE");
    tr_sembit.kv("note", "We build a Tuple signature: [Bits(b1,b2,b3), PairI64(num,den)] per element (still deterministic).");

    let id1 = normalize_str(&profile, "sign", true).unwrap();
    let id2 = normalize_str(&profile, "is_int", true).unwrap();
    let id3 = normalize_str(&profile, "den>3", true).unwrap();

    let tf = TestFamily::new(vec![
        Test { id_norm: id1.clone(), f: t_sign },
        Test { id_norm: id2.clone(), f: t_is_int },
        Test { id_norm: id3.clone(), f: t_den_gt_3 },
    ]);

    let tests_hash = tests_hash_hex(&tf, "impl:static_v1_tuple_sig");
    tr_sembit.kv("tests_hash_hex", &tests_hash);
    tr_sembit.kv("test_id_1", &id1);
    tr_sembit.kv("test_id_2", &id2);
    tr_sembit.kv("test_id_3", &id3);

    tr_sembit.section("DOMAIN DIGEST (QE)");
    tr_sembit.kv("domain_digest_hex(QE)", &qe_digest);

    tr_sembit.section("QUOTIENT: EXECUTE TESTS → BUILD SIGNATURES → PARTITION");
    let q: Quotient<QE> = Quotient::from_signatures(&domain_qe, |x| {
        let bits = tf.signature(x);
        Signature::Tuple(vec![
            Signature::Bits(bits),
            Signature::PairI64(x.num(), x.den()),
        ])
    });
    tr_sembit.kv("q.classes", &format!("{}", q.size()));

    let h = sem_entropy_bits(q.size());
    tr_sembit.kv("sem_entropy_bits(classes)", &format!("{h}"));

    let qdig = quotient_digest_hex(&q);
    tr_sembit.kv("quotient_digest_hex", &qdig);

    tr_sembit.section("SEMBITS CERT: EMBED UPSTREAM HASHES");
    let sb_cert = sembit_kernel_cert(
        &asc7_hash,
        &conf_hash,
        &tests_hash,
        &qe_digest,
        q.size(),
        h,
        &qdig,
    );
    let sb_hash = trace_kernel(&mut tr_sembit, "sembit", &sb_cert);

    tr_sembit.section("CERT CHAIN: asc7 → confusables → sembit");
    let chain = CertChain::build(vec![
        CertItem { name: "asc7".to_string(), hash_hex: asc7_hash.clone() },
        CertItem { name: "asc7_confusables".to_string(), hash_hex: conf_hash.clone() },
        CertItem { name: "sembit".to_string(), hash_hex: sb_hash.clone() },
    ]);
    tr_sembit.kv("chain_hash", &chain.chain_hash_hex);

    tr_sembit.section("SUMMARY (FOR HUMANS)");
    let mut summary = BTreeMap::new();
    summary.insert("asc7_hash".to_string(), asc7_hash);
    summary.insert("confusables_hash".to_string(), conf_hash);
    summary.insert("domain_qe_digest".to_string(), qe_digest);
    summary.insert("domain_ne_digest".to_string(), ne_digest);
    summary.insert("domain_ze_digest".to_string(), ze_digest);
    summary.insert("tests_hash".to_string(), tests_hash);
    summary.insert("sembit_hash".to_string(), sb_hash);
    summary.insert("chain_hash".to_string(), chain.chain_hash_hex);

    let json = serde_json::to_string_pretty(&summary).unwrap();
    tr_sembit.line(&json);

    tr_sembit.section("OUTPUT FILES");
    tr_sembit.kv("structural_log", &tr_struct.path().display().to_string());
    tr_sembit.kv("sembits_log", &tr_sembit.path().display().to_string());
    tr_sembit.kv("asc7_log", &tr_asc7.path().display().to_string());
}
