use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::role::{CharRole, classify_role};
use collapse_core::canon::Canon;
use collapse_core::cert::KernelCert;

/// Universe: printable ASCII 0x20..=0x7E (95 chars)
pub fn ascii_universe() -> Vec<char> {
    (0x20u8..=0x7Eu8).map(|b| b as char).collect()
}

#[derive(Clone, Debug)]
struct Dsu {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl Dsu {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect(), rank: vec![0; n] }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            let p = self.parent[x];
            self.parent[x] = self.find(p);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let mut rx = self.find(x);
        let mut ry = self.find(y);
        if rx == ry { return; }
        if self.rank[rx] < self.rank[ry] {
            std::mem::swap(&mut rx, &mut ry);
        }
        self.parent[ry] = rx;
        if self.rank[rx] == self.rank[ry] {
            self.rank[rx] += 1;
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asc7ProfileParams {
    pub name: String,
    pub syntax_strict: bool,
    pub glyph_classes: Vec<Vec<char>>,
    pub case_pairs: Vec<(char, char)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asc7Profile {
    pub params: Asc7ProfileParams,
    pub universe: Vec<char>,         // U
    pub rep_map: Vec<char>,          // U-indexed -> representative in W
    pub witness_alphabet: Vec<char>, // W
    pub graph_hash: [u8; 32],
}

fn pick_rep(class: &[char]) -> char {
    if let Some(&c) = class.iter().find(|&&c| c.is_ascii_lowercase()) {
        return c;
    }
    if let Some(&c) = class.iter().find(|&&c| c.is_ascii_digit()) {
        return c;
    }
    *class.iter().min().unwrap()
}

impl Asc7Profile {
    pub fn compile(params: Asc7ProfileParams) -> Self {
        let universe = ascii_universe();
        let n = universe.len();

        let mut idx: HashMap<char, usize> = HashMap::new();
        for (i, ch) in universe.iter().enumerate() {
            idx.insert(*ch, i);
        }

        let mut dsu = Dsu::new(n);

        let mut try_union = |c1: char, c2: char, syntax_strict: bool| {
            if let (Some(&i1), Some(&i2)) = (idx.get(&c1), idx.get(&c2)) {
                if syntax_strict {
                    let r1 = classify_role(c1);
                    let r2 = classify_role(c2);
                    let both_non_delim = r1 != CharRole::Delimiter && r2 != CharRole::Delimiter;
                    if !(r1 == r2 || both_non_delim) {
                        return;
                    }
                }
                dsu.union(i1, i2);
            }
        };

        for class in &params.glyph_classes {
            for i in 0..class.len() {
                for j in (i + 1)..class.len() {
                    try_union(class[i], class[j], params.syntax_strict);
                }
            }
        }

        for (lo, hi) in &params.case_pairs {
            try_union(*lo, *hi, params.syntax_strict);
        }

        let mut class_map: HashMap<usize, Vec<char>> = HashMap::new();
        for (i, ch) in universe.iter().enumerate() {
            let root = dsu.find(i);
            class_map.entry(root).or_default().push(*ch);
        }

        let mut witness_alphabet = Vec::new();
        let mut rep_map = vec!['\0'; n];

        for (_root, class) in &class_map {
            let rep = pick_rep(class);
            witness_alphabet.push(rep);
            for ch in class {
                rep_map[idx[ch]] = rep;
            }
        }

        witness_alphabet.sort();

        // Graph hash covers: universe bytes, equivalence classes, witness alphabet
        let mut hasher = Sha256::new();
        for ch in &universe {
            hasher.update(&[*ch as u8]);
        }

        // Sort classes by representative to be deterministic
        let mut classes: Vec<Vec<char>> = class_map.values().cloned().collect();
        classes.sort_by_key(|cls| pick_rep(cls));
        for cls in &classes {
            hasher.update(&[0u8]);
            let mut sorted = cls.clone();
            sorted.sort();
            for ch in &sorted {
                hasher.update(&[*ch as u8]);
            }
        }

        hasher.update(&[1u8]);
        for ch in &witness_alphabet {
            hasher.update(&[*ch as u8]);
        }

        let graph_hash: [u8; 32] = hasher.finalize().into();

        Self { params, universe, rep_map, witness_alphabet, graph_hash }
    }

    pub fn rep(&self, ch: char) -> Option<char> {
        if !(0x20u8..=0x7Eu8).contains(&(ch as u8)) {
            return None;
        }
        let i = (ch as u8 - 0x20) as usize;
        Some(self.rep_map[i])
    }

    pub fn code_safe() -> Self {
        Self::compile(Asc7ProfileParams {
            name: "code_safe".to_string(),
            syntax_strict: true,
            glyph_classes: vec![
                vec!['0', 'O', 'o'],
                vec!['1', 'l', 'I', '|'],
                vec!['\'', '`'],
            ],
            case_pairs: vec![],
        })
    }

    pub fn auth_safe() -> Self {
        let mut case_pairs = Vec::new();
        for (lo, hi) in ('a'..='z').zip('A'..='Z') {
            case_pairs.push((lo, hi));
        }
        Self::compile(Asc7ProfileParams {
            name: "auth_safe".to_string(),
            syntax_strict: true,
            glyph_classes: vec![
                vec!['0', 'O', 'o'],
                vec!['1', 'l', 'I', '|'],
                vec!['\'', '`'],
            ],
            case_pairs,
        })
    }
}

/// Collapse kernel cert for ASC7.
/// Payload is canonical (no floats); kernel_hash = sha256(canon(payload)).
pub fn asc7_kernel_cert(p: &Asc7Profile) -> KernelCert {
    let mut obj = BTreeMap::new();
    obj.insert("profile_name".to_string(), Canon::Str(p.params.name.clone()));
    obj.insert("syntax_strict".to_string(), Canon::Bool(p.params.syntax_strict));
    obj.insert("witness_len".to_string(), Canon::U64(p.witness_alphabet.len() as u64));
    obj.insert("graph_hash_hex".to_string(), Canon::Str(hex::encode(p.graph_hash)));
    KernelCert::new("asc7", "1.0.0", Canon::Obj(obj))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asc7KernelCert {
    pub graph_hash_hex: String,
    pub profile_name: String,
    pub syntax_strict: bool,
    pub witness_len: u64,
}

impl Asc7KernelCert {
    pub fn from_profile(p: &Asc7Profile) -> Self {
        Self {
            graph_hash_hex: hex::encode(p.graph_hash),
            profile_name: p.params.name.clone(),
            syntax_strict: p.params.syntax_strict,
            witness_len: p.witness_alphabet.len() as u64,
        }
    }

    pub fn to_canon(&self) -> Canon {
        let mut obj = BTreeMap::new();
        obj.insert("graph_hash_hex".to_string(), Canon::Str(self.graph_hash_hex.clone()));
        obj.insert("profile_name".to_string(), Canon::Str(self.profile_name.clone()));
        obj.insert("syntax_strict".to_string(), Canon::Bool(self.syntax_strict));
        obj.insert("witness_len".to_string(), Canon::U64(self.witness_len));
        Canon::Obj(obj)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticPredicateDef {
    pub bit_index: u8,
    pub id: u8,
    pub kind: String,
    pub name: String,
    pub resource_hash_hex: Option<String>,
}

impl SemanticPredicateDef {
    pub fn to_canon(&self) -> Canon {
        let mut obj = BTreeMap::new();
        obj.insert("bit_index".to_string(), Canon::U64(self.bit_index as u64));
        obj.insert("id".to_string(), Canon::U64(self.id as u64));
        obj.insert("kind".to_string(), Canon::Str(self.kind.clone()));
        obj.insert("name".to_string(), Canon::Str(self.name.clone()));
        match &self.resource_hash_hex {
            Some(v) => obj.insert("resource_hash_hex".to_string(), Canon::Str(v.clone())),
            None => obj.insert("resource_hash_hex".to_string(), Canon::Null),
        };
        Canon::Obj(obj)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asc7SemanticKernelCert {
    pub ablation_rule: String,
    pub base_kernel_hash_hex: String,
    pub filter_rule: String,
    pub predicate_registry_version: String,
    pub predicates: Vec<SemanticPredicateDef>,
}

impl Asc7SemanticKernelCert {
    pub fn to_canon(&self) -> Canon {
        let mut obj = BTreeMap::new();
        obj.insert("ablation_rule".to_string(), Canon::Str(self.ablation_rule.clone()));
        obj.insert("base_kernel_hash_hex".to_string(), Canon::Str(self.base_kernel_hash_hex.clone()));
        obj.insert("filter_rule".to_string(), Canon::Str(self.filter_rule.clone()));
        obj.insert("predicate_registry_version".to_string(), Canon::Str(self.predicate_registry_version.clone()));
        obj.insert("predicates".to_string(), Canon::Arr(self.predicates.iter().map(|p| p.to_canon()).collect()));
        Canon::Obj(obj)
    }

    pub fn to_kernel_cert(&self) -> KernelCert {
        KernelCert::new("asc7_semantic", "1.0.0", self.to_canon())
    }
}

pub fn semantic_mask_value(bit_index: u8, enabled: bool) -> (u64, u64) {
    let bit = 1u64 << bit_index;
    let mask = bit;
    let value = if enabled { bit } else { 0 };
    (mask, value)
}

pub fn signature_matches(sig: u64, mask: u64, value: u64) -> bool {
    (sig & mask) == value
}

pub fn ablate_signature(sig: u64, keep_mask: u64) -> u64 {
    sig & keep_mask
}

pub fn asc7_semantic_kernel_cert(base_kernel_hash_hex: &str, predicates: Vec<SemanticPredicateDef>) -> KernelCert {
    Asc7SemanticKernelCert {
        ablation_rule: "ablate_signature(sig, keep_mask) = sig & keep_mask".to_string(),
        base_kernel_hash_hex: base_kernel_hash_hex.to_string(),
        filter_rule: "SET_BIT(mask,value): match iff (sig & mask) == value".to_string(),
        predicate_registry_version: "1.0.0".to_string(),
        predicates,
    }.to_kernel_cert()
}
