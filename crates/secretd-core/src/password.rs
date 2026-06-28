//! Password generation, AWS GetRandomPassword-compatible.
use rand::{thread_rng, Rng};

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const PUNCTUATION: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const SPACE: &[u8] = b" ";

pub struct PasswordOptions {
    pub length: usize,
    pub exclude_uppercase: bool,
    pub exclude_lowercase: bool,
    pub exclude_numbers: bool,
    pub exclude_punctuation: bool,
    pub include_space: bool,
    pub exclude_characters: String,
    pub require_each_included_type: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 32,
            exclude_uppercase: false,
            exclude_lowercase: false,
            exclude_numbers: false,
            exclude_punctuation: false,
            include_space: false,
            exclude_characters: String::new(),
            require_each_included_type: true,
        }
    }
}

pub fn generate_password(opts: &PasswordOptions) -> Result<String, &'static str> {
    if opts.length == 0 || opts.length > 4096 {
        return Err("length must be between 1 and 4096");
    }

    let excluded: std::collections::HashSet<u8> = opts.exclude_characters.bytes().collect();

    let mut charset: Vec<u8> = Vec::new();
    let mut required_sets: Vec<Vec<u8>> = Vec::new();

    let mut add_set = |chars: &[u8]| {
        let filtered: Vec<u8> = chars.iter().copied().filter(|c| !excluded.contains(c)).collect();
        if !filtered.is_empty() {
            charset.extend_from_slice(&filtered);
            filtered
        } else {
            vec![]
        }
    };

    if !opts.exclude_uppercase {
        let s = add_set(UPPERCASE);
        if opts.require_each_included_type && !s.is_empty() { required_sets.push(s); }
    }
    if !opts.exclude_lowercase {
        let s = add_set(LOWERCASE);
        if opts.require_each_included_type && !s.is_empty() { required_sets.push(s); }
    }
    if !opts.exclude_numbers {
        let s = add_set(DIGITS);
        if opts.require_each_included_type && !s.is_empty() { required_sets.push(s); }
    }
    if !opts.exclude_punctuation {
        let s = add_set(PUNCTUATION);
        if opts.require_each_included_type && !s.is_empty() { required_sets.push(s); }
    }
    if opts.include_space {
        let s = add_set(SPACE);
        if opts.require_each_included_type && !s.is_empty() { required_sets.push(s); }
    }

    if charset.is_empty() {
        return Err("no characters available after exclusions");
    }
    if required_sets.len() > opts.length {
        return Err("length too short to include all required character types");
    }

    let mut rng = thread_rng();
    let mut password: Vec<u8> = Vec::with_capacity(opts.length);

    // Satisfy required sets first
    for set in &required_sets {
        password.push(set[rng.gen_range(0..set.len())]);
    }

    // Fill remaining with full charset
    while password.len() < opts.length {
        password.push(charset[rng.gen_range(0..charset.len())]);
    }

    // Shuffle to avoid predictable positions
    use rand::seq::SliceRandom;
    password.shuffle(&mut rng);

    Ok(String::from_utf8(password).unwrap())
}
