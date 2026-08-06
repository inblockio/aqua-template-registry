//! Registry name validation and normalization.
//!
//! This module is a faithful port of `aqua-rs-sdk`'s `src/registry/name.rs`
//! (Apache-2.0). It implements the character, script, length, and case rules
//! from `spec-type-registry.md` section 3.3, "Name Character Rules".
//!
//! Any behavioral divergence from the SDK's `NameValidator` silently breaks
//! name resolution compatibility between this registry and the SDK: the two
//! sides could accept, reject, or canonicalize the same input differently.
//! Do not "improve" the algorithm, reorder its validation steps, or change
//! the case-folding rule without also changing the SDK. The crate's `NOTICE`
//! file credits the original `aqua-rs-sdk` authors for this logic.
//!
//! Beyond the ported logic, this module adds qualified-name helpers
//! (`validate_qualified_name` and `qualified`) for the `<vendor>/<name>`
//! form used throughout the registry, plus named length constants in place
//! of the SDK's bare `64` / `128` literals.

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use unicode_script::{Script, UnicodeScript};

/// Maximum length, in Unicode scalar values after NFC normalization, of a
/// vendor name (spec-type-registry.md 3.3, rule 5).
pub const MAX_VENDOR_NAME_LEN: usize = 64;

/// Maximum length, in Unicode scalar values after NFC normalization, of a
/// template name (spec-type-registry.md 3.3, rule 5).
pub const MAX_TEMPLATE_NAME_LEN: usize = 128;

/// Validation error for registry names.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum NameError {
    /// The name was empty, or became empty after NFC normalization.
    #[error("name is empty")]
    Empty,
    /// Too many Unicode scalar values: (actual, maximum).
    #[error("name too long: {0} scalars (max {1})")]
    TooLong(usize, usize),
    /// A character outside the allowed categories: (code point, character).
    #[error("name contains disallowed character U+{0:04X} ({1})")]
    DisallowedCharacter(u32, char),
    /// Two different Unicode scripts in one name component: (first, second).
    #[error("name mixes scripts: found {0} and {1}")]
    MixedScripts(String, String),
    /// The name began or ended with a hyphen, underscore, or dot.
    #[error("name must not start or end with a separator (hyphen, underscore, or dot)")]
    StartsOrEndsWithSeparator,
}

/// Validates and normalizes registry names per spec section 3.3.
pub struct NameValidator;

impl NameValidator {
    /// Vendor name: max `MAX_VENDOR_NAME_LEN` Unicode scalar values (after NFC
    /// normalization).
    pub fn validate_vendor_name(name: &str) -> Result<String, NameError> {
        Self::validate(name, MAX_VENDOR_NAME_LEN)
    }

    /// Template name: max `MAX_TEMPLATE_NAME_LEN` Unicode scalar values (after
    /// NFC normalization).
    pub fn validate_template_name(name: &str) -> Result<String, NameError> {
        Self::validate(name, MAX_TEMPLATE_NAME_LEN)
    }

    /// Core validation: NFC normalize, check length, check characters, check script isolation.
    /// Returns the NFC-normalized, case-folded form of the name on success.
    fn validate(name: &str, max_len: usize) -> Result<String, NameError> {
        // Step 1: NFC normalization
        let normalized: String = name.nfc().collect();

        if normalized.is_empty() {
            return Err(NameError::Empty);
        }

        // Step 2: Length check (Unicode scalar count after normalization)
        let scalar_count = normalized.chars().count();
        if scalar_count > max_len {
            return Err(NameError::TooLong(scalar_count, max_len));
        }

        // Step 3: Separator boundary check (must not start or end with - _ .)
        let first = normalized.chars().next().unwrap();
        let last = normalized.chars().next_back().unwrap();
        if is_separator(first) || is_separator(last) {
            return Err(NameError::StartsOrEndsWithSeparator);
        }

        // Step 4: Character category and script validation
        let mut primary_script: Option<Script> = None;
        let mut primary_script_name = String::new();

        for ch in normalized.chars() {
            // Separators are always allowed anywhere except boundaries
            if is_separator(ch) {
                continue;
            }

            // Check allowed categories: letters, decimal digits.
            // Reject everything else (whitespace, control chars, symbols, emoji, etc.)
            if !is_allowed_category(ch) {
                return Err(NameError::DisallowedCharacter(ch as u32, ch));
            }

            // Script isolation: track which non-Common/non-Inherited script is used.
            let script = ch.script();
            if script == Script::Common || script == Script::Inherited {
                continue; // These mix freely with any script.
            }

            match &primary_script {
                None => {
                    primary_script = Some(script);
                    primary_script_name = script_name(script);
                }
                Some(ps) if *ps == script => {
                    // Same script, fine.
                }
                Some(_) => {
                    return Err(NameError::MixedScripts(
                        primary_script_name.clone(),
                        script_name(script),
                    ));
                }
            }
        }

        // Step 5: Case folding for Latin-script names (canonical storage = lowercase).
        // For scripts without case distinction, NFC is sufficient.
        let canonical = if matches!(primary_script, None | Some(Script::Latin)) {
            normalized.to_lowercase()
        } else {
            normalized
        };

        Ok(canonical)
    }
}

/// Splits a qualified `<vendor>/<name>` string on the first `/` and validates each half.
///
/// `/` is the only namespace separator recognized in a qualified name. Names
/// themselves can never contain `/`: the character-category rules in
/// `NameValidator::validate` already reject it as a disallowed character, since
/// it is neither a letter, a digit, nor one of the three allowed separators
/// (hyphen, underscore, dot). This means a qualified name with more than one
/// `/` cannot ever validate: the first `/` splits vendor from name, and any
/// remaining `/` in the name half is rejected as `DisallowedCharacter`.
///
/// Returns the canonical `(vendor, name)` pair, each already NFC-normalized
/// and case-folded per [`NameValidator::validate_vendor_name`] and
/// [`NameValidator::validate_template_name`].
///
/// If `qualified` contains no `/`, or either half is empty, this returns
/// `NameError::Empty`.
pub fn validate_qualified_name(qualified: &str) -> Result<(String, String), NameError> {
    let (vendor_part, name_part) = match qualified.split_once('/') {
        Some(parts) => parts,
        None => return Err(NameError::Empty),
    };

    let vendor = NameValidator::validate_vendor_name(vendor_part)?;
    let name = NameValidator::validate_template_name(name_part)?;

    Ok((vendor, name))
}

/// Joins an already-canonical vendor and name into a qualified `<vendor>/<name>` string.
///
/// This does not validate or normalize its inputs. Callers are expected to
/// pass parts that already went through [`NameValidator::validate_vendor_name`]
/// and [`NameValidator::validate_template_name`] (for example, the pair
/// returned by [`validate_qualified_name`]).
pub fn qualified(vendor: &str, name: &str) -> String {
    format!("{vendor}/{name}")
}

/// Returns true for separator characters (hyphen, underscore, dot).
fn is_separator(ch: char) -> bool {
    matches!(ch, '-' | '_' | '.')
}

/// Returns true for characters allowed in names (letters, decimal digits, separators).
fn is_allowed_category(ch: char) -> bool {
    // Unicode letters (category L*)
    if ch.is_alphabetic() {
        return true;
    }
    // Unicode decimal digits (category Nd)
    if ch.is_ascii_digit() || (ch.is_numeric() && !ch.is_ascii()) {
        return true;
    }
    // Separators (already handled at boundary check, but allowed in body)
    if is_separator(ch) {
        return true;
    }
    false
}

/// Returns a human-readable name for a Unicode script.
fn script_name(script: Script) -> String {
    format!("{:?}", script)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Ported verbatim from aqua-rs-sdk's src/registry/name.rs ---

    #[test]
    fn test_simple_latin() {
        // Pure lowercase Latin passes through unchanged.
        assert_eq!(
            NameValidator::validate_vendor_name("inblock"),
            Ok("inblock".to_string())
        );
    }

    #[test]
    fn test_latin_uppercase_folded() {
        // Latin script is case-folded to lowercase for canonical storage.
        assert_eq!(
            NameValidator::validate_vendor_name("InBlock"),
            Ok("inblock".to_string())
        );
    }

    #[test]
    fn test_latin_with_separators() {
        // Hyphen and underscore are allowed in the body.
        assert_eq!(
            NameValidator::validate_vendor_name("acme-corp"),
            Ok("acme-corp".to_string())
        );
        assert_eq!(
            NameValidator::validate_vendor_name("acme_corp"),
            Ok("acme_corp".to_string())
        );
    }

    #[test]
    fn test_sub_namespace_dot() {
        // Dot is allowed for sub-namespacing within a template name.
        assert_eq!(
            NameValidator::validate_template_name("identity.email"),
            Ok("identity.email".to_string())
        );
    }

    #[test]
    fn test_cyrillic() {
        // Pure Cyrillic is allowed.
        let result = NameValidator::validate_vendor_name("инблок");
        assert!(result.is_ok(), "Cyrillic name should be allowed");
    }

    #[test]
    fn test_han_script() {
        // Pure CJK is allowed, no case folding.
        let result = NameValidator::validate_vendor_name("阿里巴巴");
        assert!(result.is_ok(), "Han script should be allowed");
    }

    #[test]
    fn test_mixed_latin_cyrillic_rejected() {
        // "inblоck" mixes Latin 'i','n','b','l','c','k' with Cyrillic 'о'.
        let mixed = "inbl\u{043E}ck"; // Cyrillic small letter 'o'
        let result = NameValidator::validate_vendor_name(mixed);
        assert!(
            matches!(result, Err(NameError::MixedScripts(_, _))),
            "Mixed scripts should be rejected"
        );
    }

    #[test]
    fn test_starts_with_separator_rejected() {
        // Boundary check rejects a leading separator.
        assert_eq!(
            NameValidator::validate_vendor_name("-inblock"),
            Err(NameError::StartsOrEndsWithSeparator)
        );
    }

    #[test]
    fn test_ends_with_separator_rejected() {
        // Boundary check rejects a trailing separator.
        assert_eq!(
            NameValidator::validate_vendor_name("inblock-"),
            Err(NameError::StartsOrEndsWithSeparator)
        );
    }

    #[test]
    fn test_whitespace_rejected() {
        // Whitespace (category Zs) is not an allowed category.
        let result = NameValidator::validate_vendor_name("in block");
        assert!(
            matches!(result, Err(NameError::DisallowedCharacter(_, ' '))),
            "Whitespace must be rejected"
        );
    }

    #[test]
    fn test_control_char_rejected() {
        // Invisible/control characters (e.g. zero-width space) are rejected.
        let result = NameValidator::validate_vendor_name("in\u{200B}block");
        assert!(
            matches!(result, Err(NameError::DisallowedCharacter(_, _))),
            "Control/invisible chars must be rejected"
        );
    }

    #[test]
    fn test_emoji_rejected() {
        // Emoji are not letters or digits, so they are rejected.
        let result = NameValidator::validate_vendor_name("inblock\u{1F600}");
        assert!(
            matches!(result, Err(NameError::DisallowedCharacter(_, _))),
            "Emoji must be rejected"
        );
    }

    #[test]
    fn test_empty_rejected() {
        // The empty string is always rejected.
        assert_eq!(
            NameValidator::validate_vendor_name(""),
            Err(NameError::Empty)
        );
    }

    #[test]
    fn test_too_long_vendor() {
        // One scalar past the vendor limit is rejected.
        let long: String = "a".repeat(MAX_VENDOR_NAME_LEN + 1);
        let result = NameValidator::validate_vendor_name(&long);
        assert!(
            matches!(result, Err(NameError::TooLong(65, 64))),
            "Name of 65 chars should exceed vendor limit"
        );
    }

    #[test]
    fn test_exactly_max_vendor() {
        // Exactly at the vendor limit passes.
        let exact: String = "a".repeat(MAX_VENDOR_NAME_LEN);
        assert!(
            NameValidator::validate_vendor_name(&exact).is_ok(),
            "64-char name at vendor limit should pass"
        );
    }

    #[test]
    fn test_too_long_template() {
        // One scalar past the template limit is rejected.
        let long: String = "a".repeat(MAX_TEMPLATE_NAME_LEN + 1);
        let result = NameValidator::validate_template_name(&long);
        assert!(
            matches!(result, Err(NameError::TooLong(129, 128))),
            "Name of 129 chars should exceed template limit"
        );
    }

    #[test]
    fn test_nfc_normalization() {
        // A combining sequence (e + combining acute) normalizes to precomposed NFC.
        let combining = "cafe\u{0301}"; // 'e' + combining acute accent
        let result = NameValidator::validate_vendor_name(combining);
        assert!(result.is_ok());
        assert!(result.unwrap().contains('\u{00E9}'));
    }

    #[test]
    fn test_digits_allowed() {
        // ASCII digits are an allowed category.
        assert_eq!(
            NameValidator::validate_vendor_name("acme2024"),
            Ok("acme2024".to_string())
        );
    }

    // --- Additional vectors, not present in the original file ---

    #[test]
    fn test_greek_pure_script_accepted() {
        // Pure Greek is allowed, same script-isolation rule as Cyrillic/Han.
        let result = NameValidator::validate_vendor_name("ελληνικα");
        assert!(result.is_ok(), "Greek name should be allowed");
    }

    #[test]
    fn test_greek_latin_mixed_rejected() {
        // Latin 'a','b','c' plus Greek 'α' mixes two non-Common scripts.
        let mixed = "abc\u{03B1}"; // Greek small letter alpha
        let result = NameValidator::validate_vendor_name(mixed);
        assert!(
            matches!(result, Err(NameError::MixedScripts(_, _))),
            "Latin+Greek mix should be rejected"
        );
    }

    #[test]
    fn test_arabic_no_case_folding() {
        // Arabic has no case distinction, so the canonical form equals the
        // NFC-normalized input verbatim (no to_lowercase() applied, since
        // primary_script is Some(Script::Arabic), not None or Latin).
        let name = "\u{0645}\u{0631}\u{062D}\u{0628}\u{0627}"; // "مرحبا"
        assert_eq!(
            NameValidator::validate_vendor_name(name),
            Ok(name.to_string())
        );
    }

    #[test]
    fn test_han_name_unchanged() {
        // Han script has no case distinction: output equals input exactly.
        let name = "阿里巴巴";
        assert_eq!(
            NameValidator::validate_vendor_name(name),
            Ok(name.to_string())
        );
    }

    #[test]
    fn test_digits_and_multiple_separators_in_template_body() {
        // Hyphen, dot, and underscore may all appear in one name body.
        assert_eq!(
            NameValidator::validate_template_name("acme-corp.eu_2024"),
            Ok("acme-corp.eu_2024".to_string())
        );
    }

    #[test]
    fn test_exactly_max_template_len_passes_and_one_more_fails() {
        // Boundary check at the template limit, mirroring the vendor boundary tests.
        let exact: String = "a".repeat(MAX_TEMPLATE_NAME_LEN);
        assert!(NameValidator::validate_template_name(&exact).is_ok());

        let over: String = "a".repeat(MAX_TEMPLATE_NAME_LEN + 1);
        assert!(matches!(
            NameValidator::validate_template_name(&over),
            Err(NameError::TooLong(129, 128))
        ));
    }

    #[test]
    fn test_validate_qualified_name_splits_and_canonicalizes() {
        // Both halves are validated and canonicalized (lowercased, here).
        assert_eq!(
            validate_qualified_name("InBlock/Email-Claim"),
            Ok(("inblock".to_string(), "email-claim".to_string()))
        );
    }

    #[test]
    fn test_validate_qualified_name_missing_slash_is_empty_error() {
        // No '/' at all: there is no vendor/name split, so it is an Empty error.
        assert_eq!(validate_qualified_name("inblock"), Err(NameError::Empty));
    }

    #[test]
    fn test_validate_qualified_name_empty_halves_are_empty_error() {
        // A trailing slash leaves the name half empty.
        assert_eq!(validate_qualified_name("inblock/"), Err(NameError::Empty));
        // A leading slash leaves the vendor half empty.
        assert_eq!(validate_qualified_name("/email"), Err(NameError::Empty));
    }

    #[test]
    fn test_validate_qualified_name_dot_sub_namespace() {
        // Dot sub-namespacing composes with the vendor/name split.
        assert_eq!(
            validate_qualified_name("inblock/identity.email"),
            Ok(("inblock".to_string(), "identity.email".to_string()))
        );
    }

    #[test]
    fn test_validate_qualified_name_two_slashes_splits_on_first() {
        // "a/b/c" splits on the FIRST '/' into vendor "a" and name "b/c".
        // '/' is not a letter, digit, or separator, so validating "b/c" as a
        // name hits the disallowed-character check on '/' itself (U+002F).
        let result = validate_qualified_name("a/b/c");
        assert_eq!(result, Err(NameError::DisallowedCharacter('/' as u32, '/')));
    }

    #[test]
    fn test_vendor_single_letter_boundary() {
        // Length-1 vendor name is the minimum valid length, and is accepted.
        assert_eq!(
            NameValidator::validate_vendor_name("a"),
            Ok("a".to_string())
        );
    }

    #[test]
    fn test_all_separators_rejected() {
        // A name made only of separators still starts and ends with one.
        assert_eq!(
            NameValidator::validate_vendor_name("---"),
            Err(NameError::StartsOrEndsWithSeparator)
        );
    }

    #[test]
    fn test_combining_mark_nfc_exact_output() {
        // 'e' + combining acute (U+0301) must normalize to precomposed 'é'
        // (U+00E9) exactly, not merely contain it.
        assert_eq!(
            NameValidator::validate_vendor_name("cafe\u{0301}"),
            Ok("café".to_string())
        );
    }

    #[test]
    fn test_qualified_roundtrip() {
        // qualified() rejoins an already-canonical pair with a single '/'.
        let (vendor, name) = validate_qualified_name("InBlock/Email-Claim").unwrap();
        assert_eq!(qualified(&vendor, &name), "inblock/email-claim");
    }
}
