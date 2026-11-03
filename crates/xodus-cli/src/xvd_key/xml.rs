//! A small, bounded XML tree, for the Store delivery service's answers.
//!
//! The answers are SOAP envelopes, some carrying further XML escaped inside
//! an element's text. They are read into a tree of elements with local names
//! (namespace prefixes dropped), attributes and text, with hard limits on the
//! input size, the depth and the number of elements. A document type
//! declaration is refused, and only the five predefined entities and character
//! references are expanded, so nothing in an answer can make the parser fetch,
//! expand or allocate beyond those limits.

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_elements: usize,
}

/// Generous for every answer seen (the largest, SyncUpdates, is about 170 KB).
pub const LIMITS: Limits = Limits {
    max_bytes: 8 << 20,
    max_depth: 64,
    max_elements: 200_000,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Every element named `name` at any depth, this one included, in
    /// document order.
    pub fn descendants<'a>(&'a self, name: &str) -> Vec<&'a Element> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(e) = stack.pop() {
            if e.name == name {
                out.push(e);
            }
            stack.extend(e.children.iter().rev());
        }
        out
    }
}

fn local(name: &str) -> String {
    match name.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => name.to_string(),
    }
}

fn element(start: &BytesStart<'_>) -> Result<Element, String> {
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|e| format!("bad attribute: {e}"))?;
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| format!("bad attribute value: {e}"))?;
        attributes.push((local(attribute.key.as_ref()), value.into_owned()));
    }
    Ok(Element {
        name: local(start.name().as_ref()),
        attributes,
        ..Element::default()
    })
}

/// Read `input` into a tree, under `limits`. A fragment with several top-level
/// elements, as the escaped update XML is, comes back as the children of an
/// unnamed root.
pub fn parse(input: &str, limits: Limits) -> Result<Element, String> {
    if input.len() > limits.max_bytes {
        return Err(format!(
            "the answer is {} bytes, more than the {} allowed",
            input.len(),
            limits.max_bytes
        ));
    }
    let mut reader = Reader::from_str(input);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut elements = 0usize;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| format!("malformed XML at {}: {e}", reader.buffer_position()))?;
        match event {
            Event::Start(ref start) | Event::Empty(ref start) => {
                elements += 1;
                if elements > limits.max_elements {
                    return Err("the answer has too many elements".into());
                }
                let e = element(start)?;
                if matches!(event, Event::Empty(_)) {
                    stack.last_mut().unwrap().children.push(e);
                } else {
                    if stack.len() > limits.max_depth {
                        return Err("the answer is nested too deeply".into());
                    }
                    stack.push(e);
                }
            }
            Event::End(_) => {
                if stack.len() < 2 {
                    return Err("malformed XML: unbalanced end tag".into());
                }
                let done = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(done);
            }
            Event::Text(text) => stack
                .last_mut()
                .unwrap()
                .text
                .push_str(&text.xml10_content()),
            Event::CData(data) => stack
                .last_mut()
                .unwrap()
                .text
                .push_str(&data.xml10_content()),
            Event::GeneralRef(reference) => {
                let c = if reference.is_char_ref() {
                    reference
                        .resolve_char_ref()
                        .map_err(|e| format!("bad character reference: {e}"))?
                        .ok_or("bad character reference")?
                } else {
                    match &*reference.xml10_content() {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "quot" => '"',
                        "apos" => '\'',
                        other => return Err(format!("unknown entity &{other};")),
                    }
                };
                stack.last_mut().unwrap().text.push(c);
            }
            Event::DocType(_) => return Err("a document type declaration is not accepted".into()),
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if stack.len() != 1 {
        return Err("malformed XML: unclosed element".into());
    }
    Ok(stack.pop().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_attributes_text_and_entities_are_read() {
        let root = parse(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="urn:x"><s:Body a:x="1&amp;2" y='q'>a &lt;b&gt; &#65;&#x42;<![CDATA[<c>]]><Empty/></s:Body></s:Envelope>"#,
            LIMITS,
        )
        .unwrap();
        let body = root.descendants("Body")[0];
        assert_eq!(body.attribute("x"), Some("1&2"));
        assert_eq!(body.attribute("y"), Some("q"));
        assert_eq!(body.text, "a <b> AB<c>");
        assert_eq!(body.child("Empty").unwrap().name, "Empty");
    }

    #[test]
    fn hostile_or_broken_input_is_refused() {
        let doctype = r#"<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>"#;
        assert!(
            parse(doctype, LIMITS)
                .unwrap_err()
                .contains("document type")
        );
        assert!(parse("<x>&a;</x>", LIMITS).unwrap_err().contains("entity"));
        assert!(parse("<x><y></x>", LIMITS).is_err());
        assert!(parse("<x>", LIMITS).is_err());
        let deep = "<a>".repeat(100) + &"</a>".repeat(100);
        assert!(parse(&deep, LIMITS).unwrap_err().contains("deeply"));
        let small = Limits {
            max_bytes: 100,
            max_depth: 64,
            max_elements: 3,
        };
        assert!(
            parse(&"<a/>".repeat(4), small)
                .unwrap_err()
                .contains("many")
        );
        assert!(
            parse(&"x".repeat(101), small)
                .unwrap_err()
                .contains("bytes")
        );
    }
}
