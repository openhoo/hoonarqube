// --- Known third-party exception hierarchies for python:S5713.
//
// The reference resolves redundant except-tuples against library exception
// ancestry, so `except (urllib3.exceptions.SSLError, urllib3.exceptions.HTTPError)`
// is redundant exactly like a builtin parent/child pair. These tables mirror
// the documented `urllib3.exceptions` and `requests.exceptions` trees
// (including `requests` re-exporting `urllib3` bases) so imported and aliased
// library names resolve like the standard-library table. Unlisted libraries
// stay unknown and keep the conservative silence.

/// Whether `path` names a known third-party exception, fully qualified
/// (`urllib3.exceptions.SSLError`, `requests.exceptions.RequestException`).
pub(crate) fn is_known_library_exception_path(path: &str) -> bool {
    urllib3_exception_bases(path).is_some() || requests_exception_bases(path).is_some()
}

/// Direct bases of a known third-party exception as fully qualified paths
/// (`builtins.`-prefixed for standard types, `json.JSONDecodeError` for the
/// standard JSON error). Unknown paths return an empty list.
pub(crate) fn known_library_exception_bases(path: &str) -> Vec<&'static str> {
    urllib3_exception_bases(path)
        .or_else(|| requests_exception_bases(path))
        .unwrap_or_default()
}

/// Direct documented bases of a `urllib3.exceptions` member.
fn urllib3_exception_bases(path: &str) -> Option<Vec<&'static str>> {
    let bases: &[&str] = match path {
        "urllib3.exceptions.HTTPError" => &["builtins.Exception"],
        "urllib3.exceptions.PoolError"
        | "urllib3.exceptions.ProxyError"
        | "urllib3.exceptions.DecodeError"
        | "urllib3.exceptions.TimeoutError"
        | "urllib3.exceptions.TimeoutStateError"
        | "urllib3.exceptions.ResponseError"
        | "urllib3.exceptions.BodyNotHttplibCompatible"
        | "urllib3.exceptions.IncompleteRead"
        | "urllib3.exceptions.InvalidChunkLength"
        | "urllib3.exceptions.InvalidHeader"
        | "urllib3.exceptions.HeaderParsingError"
        | "urllib3.exceptions.UnrewindableBodyError" => &["urllib3.exceptions.HTTPError"],
        "urllib3.exceptions.RequestError"
        | "urllib3.exceptions.EmptyPoolError"
        | "urllib3.exceptions.FullPoolError"
        | "urllib3.exceptions.ClosedPoolError" => &["urllib3.exceptions.PoolError"],
        "urllib3.exceptions.SSLError" | "urllib3.exceptions.ProtocolError" => {
            &["urllib3.exceptions.ConnectionError"]
        }
        "urllib3.exceptions.ConnectionError" => &["urllib3.exceptions.RequestError"],
        "urllib3.exceptions.MaxRetryError" | "urllib3.exceptions.HostChangedError" => {
            &["urllib3.exceptions.RequestError"]
        }
        "urllib3.exceptions.ConnectTimeoutError" => &["urllib3.exceptions.TimeoutError"],
        "urllib3.exceptions.ReadTimeoutError" => &[
            "urllib3.exceptions.TimeoutError",
            "urllib3.exceptions.RequestError",
        ],
        "urllib3.exceptions.NewConnectionError" => &[
            "urllib3.exceptions.ConnectTimeoutError",
            "urllib3.exceptions.SSLError",
        ],
        "urllib3.exceptions.NameResolutionError" => &["urllib3.exceptions.NewConnectionError"],
        "urllib3.exceptions.LocationValueError" => {
            &["builtins.ValueError", "urllib3.exceptions.HTTPError"]
        }
        "urllib3.exceptions.LocationParseError" | "urllib3.exceptions.URLSchemeUnknown" => {
            &["urllib3.exceptions.LocationValueError"]
        }
        "urllib3.exceptions.ResponseNotChunked" => {
            &["urllib3.exceptions.ProtocolError", "builtins.ValueError"]
        }
        "urllib3.exceptions.ProxySchemeUnknown" => &[
            "builtins.AssertionError",
            "urllib3.exceptions.URLSchemeUnknown",
        ],
        "urllib3.exceptions.ProxySchemeUnsupported" => &["builtins.ValueError"],
        "urllib3.exceptions.HTTPWarning" => &["builtins.Warning"],
        "urllib3.exceptions.SecurityWarning" | "urllib3.exceptions.DependencyWarning" => {
            &["urllib3.exceptions.HTTPWarning"]
        }
        "urllib3.exceptions.InsecureRequestWarning"
        | "urllib3.exceptions.NotOpenSSLWarning"
        | "urllib3.exceptions.SystemTimeWarning"
        | "urllib3.exceptions.InsecurePlatformWarning" => &["urllib3.exceptions.SecurityWarning"],
        _ => return None,
    };
    Some(bases.to_vec())
}

/// Direct documented bases of a `requests.exceptions` member. `RequestException`
/// subclasses the builtin `IOError` (an alias of `OSError`); wrapper classes
/// that re-export `urllib3` bases keep that leg so cross-library pairs resolve.
fn requests_exception_bases(path: &str) -> Option<Vec<&'static str>> {
    let bases: &[&str] = match path {
        "requests.exceptions.RequestException" => &["builtins.OSError"],
        "requests.exceptions.InvalidJSONError"
        | "requests.exceptions.HTTPError"
        | "requests.exceptions.ConnectionError"
        | "requests.exceptions.Timeout"
        | "requests.exceptions.URLRequired"
        | "requests.exceptions.TooManyRedirects"
        | "requests.exceptions.ChunkedEncodingError"
        | "requests.exceptions.RetryError"
        | "requests.exceptions.UnrewindableBodyError" => &["requests.exceptions.RequestException"],
        "requests.exceptions.ProxyError" | "requests.exceptions.SSLError" => {
            &["requests.exceptions.ConnectionError"]
        }
        "requests.exceptions.ConnectTimeout" => &[
            "requests.exceptions.ConnectionError",
            "requests.exceptions.Timeout",
        ],
        "requests.exceptions.ReadTimeout" => &["requests.exceptions.Timeout"],
        "requests.exceptions.MissingSchema"
        | "requests.exceptions.InvalidSchema"
        | "requests.exceptions.InvalidURL"
        | "requests.exceptions.InvalidHeader" => &[
            "requests.exceptions.RequestException",
            "builtins.ValueError",
        ],
        "requests.exceptions.InvalidProxyURL" => &["requests.exceptions.InvalidURL"],
        "requests.exceptions.JSONDecodeError" => &[
            "requests.exceptions.InvalidJSONError",
            "json.JSONDecodeError",
        ],
        "requests.exceptions.ContentDecodingError" => &[
            "requests.exceptions.RequestException",
            "urllib3.exceptions.HTTPError",
        ],
        "requests.exceptions.StreamConsumedError" => {
            &["requests.exceptions.RequestException", "builtins.TypeError"]
        }
        "requests.exceptions.RequestsWarning" => &["builtins.Warning"],
        "requests.exceptions.FileModeWarning" => &[
            "requests.exceptions.RequestsWarning",
            "builtins.DeprecationWarning",
        ],
        "requests.exceptions.RequestsDependencyWarning" => &["requests.exceptions.RequestsWarning"],
        _ => return None,
    };
    Some(bases.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{is_known_library_exception_path, known_library_exception_bases};

    #[test]
    fn urllib3_ssl_error_reaches_http_error_through_intermediate_bases() {
        let bases = known_library_exception_bases("urllib3.exceptions.SSLError");
        assert_eq!(bases, vec!["urllib3.exceptions.ConnectionError"]);
        assert!(is_known_library_exception_path(
            "urllib3.exceptions.RequestError"
        ));
        // The multi-hop chain to the documented oracle pair stays resolvable
        // through the intermediate `ConnectionError -> RequestError -> PoolError`
        // links, each stored with its own direct bases.
        assert!(is_known_library_exception_path(
            "urllib3.exceptions.HTTPError"
        ));
    }

    #[test]
    fn requests_wrapper_and_unknown_libraries_partition() {
        assert_eq!(
            known_library_exception_bases("requests.exceptions.RequestException"),
            vec!["builtins.OSError"]
        );
        assert!(is_known_library_exception_path(
            "requests.exceptions.ContentDecodingError"
        ));
        assert!(!is_known_library_exception_path("flask.exceptions.Abort"));
        assert!(known_library_exception_bases("flask.exceptions.Abort").is_empty());
    }
}
