use collapse_core::quotient::{Quotient, Signature};
use crate::tests::TestFamily;

pub fn sembit_quotient<E: Clone>(domain: &[E], tf: &TestFamily<E>) -> Quotient<E> {
    Quotient::from_signatures(domain, |x| Signature::Bits(tf.signature(x)))
}
