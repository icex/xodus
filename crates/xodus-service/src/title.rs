//! The identity of the title a service was started for.
//!
//! The launcher reads it out of the game's own `MicrosoftGame.config` before
//! the game runs, the same way the runtime does, and hands it over in
//! `XODUS_TITLE_ID` (decimal, as the runtime sends it) and
//! `XODUS_TITLE_CLIENT_ID` (`MSAAppId`). An empty `XODUS_TITLE_ID` means the
//! config names no title. A title can put any identity on a request it sends,
//! including an inline config of its own, so a service bound to a title signs
//! with this one rather than with whatever the request says.
use xodus::models::xgameruntime::xuser::XSTSTokenRequest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TitleIdentity {
    id: Option<u32>,
    client_id: String,
}

impl TitleIdentity {
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::parse(
            std::env::var("XODUS_TITLE_ID").ok().as_deref(),
            std::env::var("XODUS_TITLE_CLIENT_ID").ok().as_deref(),
        )
    }

    fn parse(id: Option<&str>, client_id: Option<&str>) -> Result<Option<Self>, String> {
        let (id, client_id) = match (id, client_id) {
            (None, None) => return Ok(None),
            (Some(id), client_id) => (id.trim(), client_id.unwrap_or("").trim()),
            (None, Some(_)) => return Err("a title client ID without a title ID".into()),
        };
        let id = match id {
            "" => None,
            id if id.len() <= 10 && id.bytes().all(|c| c.is_ascii_digit()) => Some(
                id.parse::<u32>()
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or("invalid title ID")?,
            ),
            _ => return Err("invalid title ID".into()),
        };
        if client_id.len() > 64
            || !client_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-{}".contains(&c))
            || (id.is_none() && !client_id.is_empty())
        {
            return Err("invalid title client ID".into());
        }
        Ok(Some(Self {
            id,
            client_id: client_id.into(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn fixture(id: u32, client_id: &str) -> Self {
        Self {
            id: Some(id),
            client_id: client_id.into(),
        }
    }

    /// The `TitleId` field a request on behalf of this title carries.
    pub fn title_id(&self) -> String {
        self.id.map(|id| id.to_string()).unwrap_or_default()
    }

    /// The `TitleClientId` field a request on behalf of this title carries.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Whether a title's XSTS request is one this title may make: its own
    /// title claim, or no title claim at all. A request naming no title gets a
    /// token carrying the user and device only, which cannot pass for another
    /// title; the runtime asks that way to learn who is signed in. The audience
    /// is left to the title-management endpoint list, as the runtime does; a
    /// request choosing its own relying party is not the runtime's.
    pub fn admits(&self, req: &XSTSTokenRequest) -> Result<(), String> {
        let own = match (req.title(), self.id) {
            (None, _) => true,
            (Some((id, client)), Some(bound)) => {
                id == bound as i64 && client.trim().eq_ignore_ascii_case(&self.client_id)
            }
            (Some(_), None) => false,
        };
        if !own {
            return Err(format!(
                "refused an XSTS request for title {:?} (client {:?}); this service is bound to title {:?} (client {:?})",
                req.title_id,
                req.title_client_id,
                self.title_id(),
                self.client_id
            ));
        }
        if !req.relying_party.is_empty() {
            return Err(format!(
                "refused an XSTS request naming its own relying party {:?}; a title-bound service resolves it from the endpoint list",
                req.relying_party
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(title: &str, client: &str, relying_party: &str) -> XSTSTokenRequest {
        XSTSTokenRequest {
            url: "https://title.example.test/".into(),
            relying_party: relying_party.into(),
            method: "GET".into(),
            body_base64: String::new(),
            title_id: title.into(),
            title_client_id: client.into(),
        }
    }

    #[test]
    fn environment_binding_is_all_or_nothing_and_strict() {
        assert_eq!(TitleIdentity::parse(None, None), Ok(None));
        assert_eq!(
            TitleIdentity::parse(Some("1298034544"), Some("0000000048183522")),
            Ok(Some(TitleIdentity::fixture(1298034544, "0000000048183522")))
        );
        assert_eq!(
            TitleIdentity::parse(Some("1298034544"), None),
            Ok(Some(TitleIdentity::fixture(1298034544, "")))
        );
        let none = TitleIdentity::parse(Some(""), Some("")).unwrap().unwrap();
        assert_eq!(none.title_id(), "");
        for (id, client) in [
            (None, Some("client")),
            (Some("0"), None),
            (Some("4294967296"), None),
            (Some("6B9DE498"), None),
            (Some("-1"), None),
            (Some(""), Some("client")),
            (Some("1"), Some("a/b")),
        ] {
            assert!(
                TitleIdentity::parse(id, client).is_err(),
                "{id:?} {client:?}"
            );
        }
    }

    #[test]
    fn a_bound_title_gets_its_own_claim_and_nothing_else() {
        let bound = TitleIdentity::fixture(1805509784, "00000000-0000-0000-0000-00004C26E6C9");
        assert!(
            bound
                .admits(&request(
                    "1805509784",
                    "00000000-0000-0000-0000-00004c26e6c9",
                    ""
                ))
                .is_ok()
        );
        // No title claim: the runtime's own sign-in lookup asks this way, and
        // the token it gets carries the user and device only.
        for (title, client) in [("", ""), ("0", ""), ("", "another-client")] {
            assert!(bound.admits(&request(title, client, "")).is_ok());
        }
        for (title, client, relying_party) in [
            ("1298034544", "00000000-0000-0000-0000-00004C26E6C9", ""),
            ("1805509784", "00000000-0000-0000-0000-000000000000", ""),
            ("1805509784", "", ""),
            ("", "", "http://xboxlive.com"),
            (
                "1805509784",
                "00000000-0000-0000-0000-00004C26E6C9",
                "http://xboxlive.com",
            ),
        ] {
            assert!(
                bound
                    .admits(&request(title, client, relying_party))
                    .is_err()
            );
        }
        let legacy = TitleIdentity::fixture(1298034544, "");
        assert!(legacy.admits(&request("1298034544", "", "")).is_ok());
        assert!(legacy.admits(&request("1298034544", "client", "")).is_err());
        let none = TitleIdentity::parse(Some(""), None).unwrap().unwrap();
        assert!(none.admits(&request("", "", "")).is_ok());
        assert!(none.admits(&request("1298034544", "", "")).is_err());
    }
}
