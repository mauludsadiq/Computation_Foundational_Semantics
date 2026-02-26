use std::collections::HashSet;

use crate::profile::Asc7Profile;

pub fn normalize_str(profile: &Asc7Profile, s: &str, strict: bool) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match profile.rep(ch) {
            Some(rep) => out.push(rep),
            None => {
                if strict {
                    return Err(format!("Non-ASC7 char {:?} in strict mode", ch));
                } else {
                    out.push(ch);
                }
            }
        }
    }
    Ok(out)
}

pub fn verify_terminal(profile: &Asc7Profile, s: &str) -> bool {
    let wset: HashSet<char> = profile.witness_alphabet.iter().copied().collect();
    s.chars().all(|ch| wset.contains(&ch))
}
