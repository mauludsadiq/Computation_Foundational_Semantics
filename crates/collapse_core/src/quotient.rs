use std::collections::BTreeMap;

/// Stable signature types for quotients/partitions.
/// Keep this small and explicit; if you need richer, wrap it into Tuple.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Signature {
    Bits(Vec<bool>),
    Text(String),
    PairI64(i64, i64),
    Tuple(Vec<Signature>),
}

/// Deterministic quotient partition: classes are ordered by Signature ordering via BTreeMap.
#[derive(Clone, Debug)]
pub struct Quotient<U> {
    pub classes: BTreeMap<Signature, Vec<U>>,
}

impl<U: Clone> Quotient<U> {
    pub fn from_signatures(items: &[U], sig_fn: impl Fn(&U) -> Signature) -> Self {
        let mut classes: BTreeMap<Signature, Vec<U>> = BTreeMap::new();
        for u in items {
            let sig = sig_fn(u);
            classes.entry(sig).or_default().push(u.clone());
        }
        Self { classes }
    }

    pub fn size(&self) -> usize {
        self.classes.len()
    }
}
