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

fn t_positive(x: &QE) -> bool { x.num() > 0 }
fn t_integer(x: &QE) -> bool { x.den() == 1 }
fn t_den_small(x: &QE) -> bool { x.den() <= 6 }
fn t_num_even(x: &QE) -> bool { x.num() % 2 == 0 }
fn t_den_mod3(x: &QE) -> bool { x.den() % 3 == 0 }
fn t_proper(x: &QE) -> bool { x.num().abs() < x.den() }

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
    for raw in ["positive", "integer", "den<=6", "num_even", "den_mod3", "proper", "A", "a", "O", "o"] {
        let norm = normalize_str(&profile, raw, true).unwrap();
        tr_asc7.kv(&format!("normalize({raw})"), &norm);
    }

    tr_struct.section("QE DOMAIN: CONSTRUCTION");
    let domain_qe: Vec<QE> = domain_qe_bounded(50, 50);
    tr_struct.kv("domain_qe_bounded(nmax=50, dmax=50)", &format!("size={}", domain_qe.len()));
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

    tr_sembit.section("TEST FAMILY: 6-BIT COLLAPSING BUCKETS WITH PROPER SPLIT");
    tr_sembit.kv("note", "We build a Bits signature from 6 coarse predicates; the 6th splits proper vs improper fractions.");

    let id1 = normalize_str(&profile, "positive", true).unwrap();
    let id2 = normalize_str(&profile, "integer", true).unwrap();
    let id3 = normalize_str(&profile, "den<=6", true).unwrap();
    let id4 = normalize_str(&profile, "num_even", true).unwrap();
    let id5 = normalize_str(&profile, "den_mod3", true).unwrap();
    let id6 = normalize_str(&profile, "proper", true).unwrap();

    let tf = TestFamily::new(vec![
        Test { id_norm: id1.clone(), f: t_positive },
        Test { id_norm: id2.clone(), f: t_integer },
        Test { id_norm: id3.clone(), f: t_den_small },
        Test { id_norm: id4.clone(), f: t_num_even },
        Test { id_norm: id5.clone(), f: t_den_mod3 },
        Test { id_norm: id6.clone(), f: t_proper },
    ]);

    let tests_hash = tests_hash_hex(&tf, "impl:static_v3_bucket_bits_proper");
    tr_sembit.kv("tests_hash_hex", &tests_hash);
    tr_sembit.kv("test_id_1", &id1);
    tr_sembit.kv("test_id_2", &id2);
    tr_sembit.kv("test_id_3", &id3);
    tr_sembit.kv("test_id_4", &id4);
    tr_sembit.kv("test_id_5", &id5);
    tr_sembit.kv("test_id_6", &id6);

    tr_sembit.section("DOMAIN DIGEST (QE)");
    tr_sembit.kv("domain_digest_hex(QE)", &qe_digest);

    tr_sembit.section("QUOTIENT: EXECUTE TESTS → BUILD SIGNATURES → PARTITION");
    let q: Quotient<QE> = Quotient::from_signatures(&domain_qe, |x| {
        let bits = tf.signature(x);
        Signature::Bits(bits)
    });
    tr_sembit.kv("q.classes", &format!("{}", q.size()));

    let h = sem_entropy_bits(q.size());
    tr_sembit.kv("sem_entropy_bits(classes)", &format!("{h}"));
    let raw_bits = (domain_qe.len() as f64).log2();
    let saved_bits = raw_bits - h;
    let pct_saved = if raw_bits > 0.0 { (saved_bits / raw_bits) * 100.0 } else { 0.0 };
    tr_sembit.kv("raw_entropy_bits(domain)", &format!("{raw_bits:.6}"));
    tr_sembit.kv("saved_entropy_bits", &format!("{saved_bits:.6}"));
    tr_sembit.kv("compression_percent", &format!("{pct_saved:.2}%"));
    if let Some((sig, members)) = q.classes.iter().max_by_key(|(_, v)| v.len()) {
        tr_sembit.section("LARGEST CLASS");
        tr_sembit.kv("largest_class_sig", &format!("{sig:?}"));
        tr_sembit.kv("largest_class_members", &format!("{}", members.len()));
        let pct = (members.len() as f64 / domain_qe.len() as f64) * 100.0;
        tr_sembit.kv("largest_class_percent", &format!("{pct:.2}%"));
        for (i, q) in members.iter().take(8).enumerate() {
            tr_sembit.kv(&format!("example_{}", i + 1), &format!("{}/{}", q.num(), q.den()));
        }
        let mut sum_val = 0.0;
        let mut min_val = f64::INFINITY;
        let mut max_val = f64::NEG_INFINITY;
        for q in members.iter() {
            let v = q.num() as f64 / q.den() as f64;
            sum_val += v;
            if v < min_val { min_val = v; }
            if v > max_val { max_val = v; }
        }
        let avg_val = sum_val / members.len() as f64;
        tr_sembit.kv("largest_class_avg_value", &format!("{avg_val:.6}"));
        tr_sembit.kv("largest_class_min_value", &format!("{min_val:.6}"));
        tr_sembit.kv("largest_class_max_value", &format!("{max_val:.6}"));
        if let Some((small_sig, small_members)) = q.classes.iter().min_by_key(|(_, v)| v.len()) {
            tr_sembit.section("SMALLEST CLASS");
            tr_sembit.kv("smallest_class_sig", &format!("{small_sig:?}"));
            tr_sembit.kv("smallest_class_members", &format!("{}", small_members.len()));
            if let Some(first) = small_members.first() {
                tr_sembit.kv("smallest_class_example", &format!("{}/{}", first.num(), first.den()));
            }
        }
    }

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
