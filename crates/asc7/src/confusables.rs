use std::collections::BTreeMap;

use collapse_core::canon::Canon;
use collapse_core::cert::KernelCert;

pub fn confusables_min_table() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();

    m.insert("A".to_string(), "Α".to_string());
    m.insert("B".to_string(), "Β".to_string());
    m.insert("E".to_string(), "Ε".to_string());
    m.insert("I".to_string(), "Ι".to_string());
    m.insert("K".to_string(), "Κ".to_string());
    m.insert("M".to_string(), "Μ".to_string());
    m.insert("N".to_string(), "Ν".to_string());
    m.insert("O".to_string(), "Ο".to_string());
    m.insert("P".to_string(), "Ρ".to_string());
    m.insert("T".to_string(), "Τ".to_string());
    m.insert("X".to_string(), "Χ".to_string());
    m.insert("Y".to_string(), "Υ".to_string());

    m.insert("a".to_string(), "а".to_string());
    m.insert("e".to_string(), "е".to_string());
    m.insert("o".to_string(), "о".to_string());
    m.insert("p".to_string(), "р".to_string());
    m.insert("c".to_string(), "с".to_string());
    m.insert("x".to_string(), "х".to_string());
    m.insert("y".to_string(), "у".to_string());

    m
}

pub fn confusables_kernel_cert() -> KernelCert {
    let table = confusables_min_table();

    let mut obj = BTreeMap::new();
    obj.insert("table_size".to_string(), Canon::U64(table.len() as u64));

    let mut pairs = Vec::with_capacity(table.len());
    for (k, v) in table {
        let mut p = BTreeMap::new();
        p.insert("src".to_string(), Canon::Str(k));
        p.insert("dst".to_string(), Canon::Str(v));
        pairs.push(Canon::Obj(p));
    }
    obj.insert("pairs".to_string(), Canon::Arr(pairs));

    KernelCert::new("asc7_confusables", "1.0.0", Canon::Obj(obj))
}
