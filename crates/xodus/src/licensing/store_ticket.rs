//! Normalize MSA beneficiary tickets only at Microsoft Store request boundaries.
//!
//! STS delegationcompact tickets are stored as `d=` for Xbox authentication.
//! Store Collections rejects that beneficiary form with InvalidMsaTicketFormat;
//! its compact form is `t=<opaque payload>&p=`. Preserve encoding and padding,
//! and keep stored credentials and device-ticket headers unchanged.

pub fn user_ticket(ticket: String) -> String {
    match ticket.strip_prefix("d=") {
        Some(value) if !value.is_empty() => {
            if value.contains("&p=") {
                format!("t={value}")
            } else {
                format!("t={value}&p=")
            }
        }
        _ => ticket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_ticket_becomes_a_store_compact_ticket() {
        assert_eq!(
            user_ticket("d=synthetic+/payload==".into()),
            "t=synthetic+/payload==&p="
        );
    }

    #[test]
    fn an_existing_compact_ticket_and_its_policy_are_preserved() {
        let ticket = "t=synthetic%2Bpayload%3D&p=existing-policy";
        assert_eq!(user_ticket(ticket.into()), ticket);
    }

    #[test]
    fn an_existing_delegation_policy_is_not_duplicated() {
        assert_eq!(
            user_ticket("d=synthetic&p=policy".into()),
            "t=synthetic&p=policy"
        );
    }

    #[test]
    fn unsupported_and_empty_forms_are_left_for_the_service_to_reject() {
        for ticket in ["", "d=", "synthetic", "t=synthetic", "D=synthetic"] {
            assert_eq!(user_ticket(ticket.into()), ticket);
        }
    }

    #[test]
    fn formatting_a_request_does_not_modify_the_stored_ticket() {
        let stored = "d=synthetic".to_string();
        assert_eq!(user_ticket(stored.clone()), "t=synthetic&p=");
        assert_eq!(stored, "d=synthetic");
    }
}
