use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

pub fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Sha256Digest(hasher.finalize().into())
}

pub fn sha256_hex(d: Sha256Digest) -> String {
    hex::encode(d.0)
}
