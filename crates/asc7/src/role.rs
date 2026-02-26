#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CharRole {
    Letter,
    Digit,
    Delimiter,
    Punctuation,
    Space,
    Other,
}

pub fn classify_role(ch: char) -> CharRole {
    match ch {
        'a'..='z' | 'A'..='Z' => CharRole::Letter,
        '0'..='9'             => CharRole::Digit,
        '(' | ')' |
        '[' | ']' |
        '{' | '}'             => CharRole::Delimiter,
        ' ' | '\t'            => CharRole::Space,
        '!' | '"' | '#' | '$' | '%' | '&' | '\'' |
        '*' | '+' | ',' | '-' | '.' | '/' | ':' |
        ';' | '<' | '=' | '>' | '?' | '@' | '\\' |
        '^' | '_' | '`' | '|' | '~' => CharRole::Punctuation,
        _ => CharRole::Other,
    }
}
