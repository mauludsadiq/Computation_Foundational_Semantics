use crate::q_e::QE;

pub fn domain_qe_bounded(nmax: i64, dmax: i64) -> Vec<QE> {
    let mut out = Vec::new();
    for den in 1..=dmax {
        for num in -nmax..=nmax {
            out.push(QE::new(num, den));
        }
    }
    out.sort();
    out.dedup();
    out
}
