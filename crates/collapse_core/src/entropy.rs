pub fn log2_u64(n: u64) -> f64 {
    (n as f64).log2()
}

pub fn sem_entropy_bits(num_classes: usize) -> f64 {
    log2_u64(num_classes as u64)
}
