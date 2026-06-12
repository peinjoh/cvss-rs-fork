use crate::ParseError;

/// Parses a metric component into its key and value parts.
///
/// This function is shared by the CVSS v2, v3 and v4 parsers.
///
/// # Arguments
///
/// * `component` - A metric component string in the format "KEY:VALUE"
///
/// # Returns
///
/// A tuple of (key, value) where both are uppercase strings, or a ParseError if:
/// - the component is empty
/// - there is no delimiter (component does not contain `:`)
/// - the key is missing (component starts with ':')
/// - the value is missing (component ends with ':')
/// - multiple colons are present (e.g., "KEY:VALUE:FOO")
pub fn parse_kvp(component: &str) -> Result<(String, String), ParseError> {
    // check for empty component, return error if empty
    if component.is_empty() {
        return Err(ParseError::InvalidComponent {
            component: component.to_string(),
        });
    }

    // split at the first ':' delim, return error if none exists
    let (key, value) = component.split_once(':')
        .ok_or_else(|| ParseError::InvalidComponent {
        component: component.to_string(),
    })?;

    // check for empty key or value, return error if empty
    if key.is_empty() || value.is_empty() {
        return Err(ParseError::InvalidComponent {
            component: component.to_string(),
        });
    }

    // check for extra colons (more than 2 parts), return if exists
    if value.contains(':') {
        return Err(ParseError::InvalidComponent {
            component: component.to_string(),
        });
    }

    // TODO: this to_ascii_uppercase is causing part of #25, will be removed in another PR
    Ok((key.to_ascii_uppercase(), value.to_ascii_uppercase()))
}

#[cfg(test)]
mod parse_kvp_tests {
    use rstest::rstest;
    use super::*;

    #[test]
    fn test_valid_key_value_pair() {
        let (key, value) = parse_kvp("AV:N").unwrap();
        assert_eq!(key, "AV");
        assert_eq!(value, "N");
    }

    #[test]
    fn test_lowercase_converted_to_uppercase() {
        let (key, value) = parse_kvp("av:n").unwrap();
        assert_eq!(key, "AV");
        assert_eq!(value, "N");
    }

    #[rstest]
    #[case("")]
    #[case("AVN")]
    #[case("AV:")]
    #[case(":N")]
    #[case("AV:N:X")]
    fn test_invalid_component(#[case] input: &str) {
        let result = parse_kvp(input);
        assert!(matches!(result, Err(ParseError::InvalidComponent { .. })));
    }
}
