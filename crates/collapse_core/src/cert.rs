use std::collections::BTreeMap;

use crate::canon::{Canon, canon_bytes};
use crate::digest::{Sha256Digest, sha256_bytes, sha256_hex};

#[derive(Clone, Debug)]
pub struct KernelCert {
    pub kernel_name: String,
    pub kernel_version: String,
    pub payload: Canon,
    pub kernel_hash: Sha256Digest,
}

impl KernelCert {
    pub fn new(kernel_name: &str, kernel_version: &str, payload: Canon) -> Self {
        let bytes = canon_bytes(&payload);
        let kernel_hash = sha256_bytes(&bytes);
        Self {
            kernel_name: kernel_name.to_string(),
            kernel_version: kernel_version.to_string(),
            payload,
            kernel_hash,
        }
    }

    pub fn kernel_hash_hex(&self) -> String {
        sha256_hex(self.kernel_hash)
    }

    pub fn to_canon(&self) -> Canon {
        let mut obj = BTreeMap::new();
        obj.insert("kernel_name".to_string(), Canon::Str(self.kernel_name.clone()));
        obj.insert("kernel_version".to_string(), Canon::Str(self.kernel_version.clone()));
        obj.insert("payload".to_string(), self.payload.clone());
        obj.insert("kernel_hash".to_string(), Canon::Str(self.kernel_hash_hex()));
        Canon::Obj(obj)
    }
}

#[derive(Clone, Debug)]
pub struct CertItem {
    pub name: String,
    pub hash_hex: String,
}

#[derive(Clone, Debug)]
pub struct CertChain {
    pub items: Vec<CertItem>,
    pub chain_hash_hex: String,
}

pub fn cert_chain_hash(items: &[CertItem]) -> String {
    let mut arr = Vec::new();
    for it in items {
        let mut obj = BTreeMap::new();
        obj.insert("name".to_string(), Canon::Str(it.name.clone()));
        obj.insert("hash".to_string(), Canon::Str(it.hash_hex.clone()));
        arr.push(Canon::Obj(obj));
    }
    sha256_hex(sha256_bytes(&canon_bytes(&Canon::Arr(arr))))
}

impl CertChain {
    pub fn build(items: Vec<CertItem>) -> Self {
        let chain_hash_hex = cert_chain_hash(&items);
        Self { items, chain_hash_hex }
    }
}
