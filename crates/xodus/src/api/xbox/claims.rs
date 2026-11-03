//! Which Xbox Live calls need the token to say *which title* is asking.
//!
//! An XSTS token can carry a title claim, minted from a title's `TitleId` and
//! `MSAAppId`. Most services ignore it. A few scope everything they do by it,
//! and those refuse a token that does not carry the right one -- not with a
//! diagnosable error, but with a bare 403 that reads, from inside the game, as
//! "sign-in is broken" or "failed to create party".
//!
//! Worse, a *wrong* claim is not a weaker claim. Measured against a live
//! account: `POST sessiondirectory.xboxlive.com/handles/query` for a title's
//! service config answers
//!
//!   * 200, with a token carrying no title claim at all,
//!   * 403 "The requested service config cannot be accessed.", with a token
//!     claiming a different title,
//!   * 200, with a token claiming the title that owns the config.
//!
//! So a stand-in claim is worse than none, and the failure looks identical to a
//! sign-in problem. This table exists so the failure can be named instead:
//! when a request lands on one of these routes and the token has no claim to
//! give it, something says so, in words, at the moment it happens.
//!
//! It is a diagnostic, not a gate. The token always carries the running title's
//! claim when one can be minted; this only decides whether *not* having one is
//! worth complaining about.

/// A route that is scoped by title.
struct Rule {
    /// Host, matched exactly or as a suffix after a leading dot.
    host: &'static str,
    /// A fragment the path must contain, or `None` for "any path on this host".
    path: Option<&'static str>,
    /// What breaks when the claim is missing, in the user's terms.
    what: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        // MPSD: sessions, handles and the activity/party plumbing above them.
        // Every read and write is against a title's service config.
        host: "sessiondirectory.xboxlive.com",
        path: None,
        what: "multiplayer sessions, parties and invites",
    },
    Rule {
        host: "multiplayeractivity.xboxlive.com",
        path: None,
        what: "the multiplayer activity a friend joins from",
    },
    Rule {
        // Presence *for the title you are in*. The batch and people routes on
        // the same host are not scoped and answer fine without a claim.
        host: "userpresence.xboxlive.com",
        path: Some("/devices/current/titles/current"),
        what: "showing the game you are playing on your profile",
    },
    Rule {
        host: "titlestorage.xboxlive.com",
        path: None,
        what: "title storage (leaderboard blobs, saved configuration)",
    },
    Rule {
        // Writes are per-title; the read routes titles use at startup are not.
        host: "achievements.xboxlive.com",
        path: Some("/achievements/update"),
        what: "unlocking achievements",
    },
];

/// What the URL needs a title claim *for*, or `None` if it does not need one.
pub fn needs_title_claim(url: &str) -> Option<&'static str> {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host.split_once(':').map(|(h, _)| h).unwrap_or(host);
    let host = host.to_ascii_lowercase();

    RULES
        .iter()
        .find(|rule| {
            (host == rule.host || host.ends_with(&format!(".{}", rule.host)))
                && rule.path.is_none_or(|fragment| path.contains(fragment))
        })
        .map(|rule| rule.what)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_directory_is_scoped_by_title_whatever_the_route() {
        assert_eq!(
            needs_title_claim(
                "https://sessiondirectory.xboxlive.com/handles/query?include=relatedInfo"
            ),
            Some("multiplayer sessions, parties and invites")
        );
        assert!(
            needs_title_claim("https://sessiondirectory.xboxlive.com/serviceconfigs/x").is_some()
        );
    }

    /// The distinction that makes the table worth having: one host, two routes,
    /// and only one of them cares. Reporting the whole host would cry wolf on
    /// every presence batch a title makes at startup.
    #[test]
    fn presence_is_scoped_only_where_it_names_the_current_title() {
        assert!(
            needs_title_claim(
                "https://userpresence.xboxlive.com/users/xuid(1)/devices/current/titles/current"
            )
            .is_some()
        );
        assert!(needs_title_claim("https://userpresence.xboxlive.com/users/batch").is_none());
    }

    #[test]
    fn services_that_do_not_scope_by_title_are_not_reported() {
        for url in [
            "https://profile.xboxlive.com/users/batch/profile/settings",
            "https://social.xboxlive.com/users/xuid(1)/people?view=FriendList",
            "https://userstats.xboxlive.com/batch?operation=read",
            "https://collections.mp.microsoft.com/v6.0/collections/query",
        ] {
            assert!(needs_title_claim(url).is_none(), "{url}");
        }
    }

    /// Hosts arrive from a title, not from us, so the match has to survive a
    /// port, a case difference and a regional prefix without either missing a
    /// real match or claiming a lookalike domain.
    #[test]
    fn the_host_is_matched_and_not_merely_searched_for() {
        assert!(needs_title_claim("https://SessionDirectory.XboxLive.com/handles").is_some());
        assert!(needs_title_claim("https://eu.sessiondirectory.xboxlive.com/handles").is_some());
        assert!(needs_title_claim("https://sessiondirectory.xboxlive.com:443/handles").is_some());
        assert!(
            needs_title_claim("https://sessiondirectory.xboxlive.com.example.net/handles")
                .is_none(),
            "a domain that merely starts with the host is a different domain"
        );
        assert!(
            needs_title_claim("https://example.net/sessiondirectory.xboxlive.com").is_none(),
            "and the host must come from the authority, not from the path"
        );
    }
}
