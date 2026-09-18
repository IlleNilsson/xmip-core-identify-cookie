#![forbid(unsafe_code)]

//! Identify by cookie: one named cookie is the claim.
//!
//! RFC 6265 sends every cookie a client holds in one `Cookie` header, as
//! `name=value` pairs separated by `; `. The transport puts that header on
//! the arrival as `http.header.cookie`, and the identifier is built naming
//! one cookie in it — a `partner`, a `session` — whose value it presents under
//! [`xcore::mechanism::cookie`], passed and with nothing behind it. Every
//! other cookie in the header is somebody else's and is not looked at, so a
//! malformed neighbor never turns this one into an error.
//!
//! A cookie name is compared exactly as written: RFC 6265 gives it no case
//! folding, and `Session` and `session` are two cookies. The value is
//! presented without the double quotes the grammar allows around it. Where a
//! client sends the name twice the first stands, which is the order RFC 6265
//! section 5.4 gives the more specific path.
//!
//! Only a pushed Stream carries a `Cookie` header; a detected or scheduled
//! arrival presents nothing here.
//!
//! Property this technology reads: `http.header.cookie`. Evidence it writes:
//! `cookie.name`. It attaches no proof: a cookie that is a session secret
//! belongs to a technology that knows what the session is.

use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use xcore::{Arriving, Mechanism};

/// The property the transport puts the `Cookie` request header under.
pub const COOKIE_HEADER: &str = "http.header.cookie";
/// The evidence name the cookie's name rides under.
pub const COOKIE_NAME: &str = "cookie.name";

/// Reads one named cookie.
#[derive(Clone, Debug)]
pub struct CookieIdentifier {
    name: String,
}

impl CookieIdentifier {
    /// Read this cookie. The name is matched exactly, as RFC 6265 compares it.
    ///
    /// # Errors
    ///
    /// Where the name is empty or holds a character a cookie name cannot:
    /// an identifier that could never match is a configuration fault, and it
    /// is said when the identifier is built rather than never.
    pub fn named(name: &str) -> Result<Self, IdentifyError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(IdentifyError::new("the cookie to read has no name"));
        }
        if let Some(bad) = name.chars().find(|character| !is_token(*character)) {
            return Err(IdentifyError::new(format!(
                "the cookie name {name:?} holds {bad:?}, which a cookie name cannot"
            )));
        }

        Ok(Self {
            name: name.to_string(),
        })
    }

    /// The cookie this reads.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// RFC 6265 section 4.1.1: a cookie name is an RFC 7230 token.
fn is_token(character: char) -> bool {
    character.is_ascii_graphic() && !"()<>@,;:\\\"/[]?={}".contains(character)
}

/// The value of one cookie in a `Cookie` header, unquoted; the first where
/// the name appears twice.
#[must_use]
pub fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (candidate, value) = pair.split_once('=')?;
        (candidate.trim() == name).then(|| unquote(value.trim()))
    })
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}

impl TransportIdentifier for CookieIdentifier {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::cookie()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(value) = arrival
            .property(COOKIE_HEADER)
            .and_then(|header| cookie(header, &self.name))
        else {
            return Ok(None);
        };

        if value.is_empty() {
            return Err(IdentifyError::new(format!(
                "the cookie {} is present and empty",
                self.name
            )));
        }
        if value
            .chars()
            .any(|character| character.is_ascii_control() || character == '"')
        {
            return Err(IdentifyError::new(format!(
                "the cookie {} holds a control character or an unbalanced quote",
                self.name
            )));
        }

        Ok(Some(
            Presented::passed(self.mechanism(), value).with_evidence(COOKIE_NAME, &self.name),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn header(value: &str) -> Vec<(String, String)> {
        vec![(COOKIE_HEADER.to_string(), value.to_string())]
    }

    fn partner() -> CookieIdentifier {
        CookieIdentifier::named("partner").expect("a name")
    }

    #[test]
    fn a_named_cookie_is_the_claim_and_its_neighbors_are_not_looked_at() {
        let stream = stream();
        let facts = header("theme=dark; partner=partner-x; broken; lang=sv");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = partner()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "cookie");
        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(
            claim.evidence,
            vec![(COOKIE_NAME.to_string(), "partner".to_string())]
        );
    }

    #[test]
    fn a_quoted_value_is_presented_without_its_quotes_and_the_first_of_two_stands() {
        let stream = stream();
        let facts = header("partner=\"partner-x\";partner=partner-y");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = partner()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
    }

    #[test]
    fn a_cookie_name_is_compared_exactly_as_written() {
        let stream = stream();
        let facts = header("Partner=partner-x");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        assert!(partner().identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn an_arrival_without_the_cookie_presents_nothing() {
        let stream = stream();
        let other = header("theme=dark");
        let with_other = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &other);
        let bare = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &[]);

        assert!(partner().identify(&with_other).expect("read").is_none());
        assert!(partner().identify(&bare).expect("read").is_none());
    }

    #[test]
    fn a_cookie_that_is_present_and_empty_is_an_error_and_not_an_absence() {
        let stream = stream();
        let facts = header("partner=; theme=dark");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let failure = partner().identify(&arrival).expect_err("empty");

        assert_eq!(
            failure.to_string(),
            "the cookie partner is present and empty"
        );
    }

    #[test]
    fn a_name_no_cookie_could_carry_is_refused_when_the_identifier_is_built() {
        let failure = CookieIdentifier::named("part ner").expect_err("a space");

        assert!(failure.message.contains("cannot"), "{failure}");
        assert!(CookieIdentifier::named("  ").is_err());
    }

    #[test]
    fn a_scheduled_pickup_carries_no_cookie_of_the_sources() {
        let stream = stream();
        let facts = header("partner=partner-x");
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://partner/out", &facts);

        assert!(partner().identify(&arrival).expect("read").is_none());
    }
}
