//! A small XML reader for the `.cspec`/`.pspec` files (the part of Ghidra's `xml.y` +
//! `XmlDecode` the decompiler's spec loading needs): elements, attributes, character data
//! (entities and CDATA decoded). Comments, the `<?xml?>` declaration and `<!DOCTYPE>` are skipped.

use super::{err, LowlevelError, Result};

/// One element: its name, attributes in document order, child elements and character data.
#[derive(Debug, Default)]
pub(crate) struct Element {
    pub(crate) name: String,
    attrs: Vec<(String, String)>,
    pub(crate) kids: Vec<Element>,
    /// the element's own character data, children's text excluded
    pub(crate) text: String,
}

impl Element {
    /// The attribute `name`, if present.
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The attribute names, in document order.
    pub(crate) fn attr_names(&self) -> impl Iterator<Item = &str> {
        self.attrs.iter().map(|(n, _)| n.as_str())
    }

    /// The attribute `name`, or an error naming the element.
    pub(crate) fn req(&self, name: &str) -> Result<&str> {
        self.attr(name).ok_or_else(|| LowlevelError(format!("<{}>: missing attribute {name}", self.name)))
    }

    /// The attribute `name` as an integer (decimal, `0x` hex, or negative decimal), as
    /// `Decoder::readSignedInteger` reads it.
    pub(crate) fn int(&self, name: &str) -> Result<i64> {
        parse_int(self.req(name)?).ok_or_else(|| LowlevelError(format!("<{}>: bad integer in {name}", self.name)))
    }

    /// The attribute `name` as a boolean (`true`/`1`/`yes`; absent is false), as `xml_readbool`.
    pub(crate) fn flag(&self, name: &str) -> bool {
        self.attr(name).is_some_and(|v| matches!(v.as_bytes().first(), Some(b't' | b'1' | b'y')))
    }

    /// The children named `name`.
    pub(crate) fn kids_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.kids.iter().filter(move |k| k.name == name)
    }

    /// The first child named `name`.
    pub(crate) fn kid(&self, name: &str) -> Option<&Element> {
        self.kids.iter().find(|k| k.name == name)
    }
}

/// `0x` hex, decimal, or `-` decimal.
pub(crate) fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok().map(|v| v as i64),
        None => s.parse().ok(),
    }
}

/// Parse a document; returns its root element.
pub(crate) fn parse(text: &str) -> Result<Element> {
    let mut p = Parser { s: text, pos: 0 };
    p.skip_misc()?;
    let root = p.element()?;
    p.skip_misc()?;
    if p.pos != p.s.len() {
        return p.fail("content after the root element");
    }
    Ok(root)
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn fail<T>(&self, what: &str) -> Result<T> {
        let line = self.s[..self.pos].matches('\n').count() + 1;
        err(format!("XML line {line}: {what}"))
    }

    /// Skip past `end`, which must follow.
    fn skip_past(&mut self, end: &str) -> Result<()> {
        match self.rest().find(end) {
            Some(i) => {
                self.pos += i + end.len();
                Ok(())
            }
            None => self.fail(&format!("missing {end}")),
        }
    }

    /// Whitespace, comments, processing instructions and `<!DOCTYPE ...>`.
    fn skip_misc(&mut self) -> Result<()> {
        loop {
            self.pos = self.s.len() - self.rest().trim_start().len();
            let r = self.rest();
            if r.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if r.starts_with("<?") {
                self.skip_past("?>")?;
            } else if r.starts_with("<!DOCTYPE") {
                self.skip_past(">")?;
            } else {
                return Ok(());
            }
        }
    }

    fn name(&mut self) -> Result<String> {
        let r = self.rest();
        let n = r.find(|c: char| c.is_whitespace() || "/>=".contains(c)).unwrap_or(r.len());
        if n == 0 {
            return self.fail("expected a name");
        }
        self.pos += n;
        Ok(r[..n].to_string())
    }

    fn element(&mut self) -> Result<Element> {
        if !self.rest().starts_with('<') {
            return self.fail("expected an element");
        }
        self.pos += 1;
        let mut el = Element { name: self.name()?, ..Element::default() };
        loop {
            self.pos = self.s.len() - self.rest().trim_start().len();
            let r = self.rest();
            if let Some(after) = r.strip_prefix("/>") {
                self.pos = self.s.len() - after.len();
                return Ok(el);
            }
            if r.starts_with('>') {
                self.pos += 1;
                break;
            }
            let name = self.name()?;
            let r = self.rest().trim_start();
            let Some(r) = r.strip_prefix('=') else { return self.fail("expected = after an attribute name") };
            let r = r.trim_start();
            let Some(q) = r.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                return self.fail("expected a quoted attribute value");
            };
            let Some(end) = r[1..].find(q) else { return self.fail("unterminated attribute value") };
            el.attrs.push((name, unescape(&r[1..=end])));
            self.pos = self.s.len() - r.len() + end + 2;
        }
        self.content(&mut el)?;
        Ok(el)
    }

    /// Children and character data up to the element's end tag.
    fn content(&mut self, el: &mut Element) -> Result<()> {
        loop {
            let r = self.rest();
            let Some(lt) = r.find('<') else { return self.fail(&format!("missing </{}>", el.name)) };
            el.text.push_str(&unescape(&r[..lt]));
            self.pos += lt;
            let r = self.rest();
            if let Some(cdata) = r.strip_prefix("<![CDATA[") {
                let Some(end) = cdata.find("]]>") else { return self.fail("unterminated CDATA") };
                el.text.push_str(&cdata[..end]);
                self.pos += "<![CDATA[".len() + end + 3;
            } else if r.starts_with("<!--") || r.starts_with("<?") {
                self.skip_misc()?;
            } else if let Some(close) = r.strip_prefix("</") {
                let end = close.find('>').unwrap_or(close.len());
                if close[..end].trim() != el.name {
                    return self.fail(&format!("</{}> closes <{}>", close[..end].trim(), el.name));
                }
                self.pos += end + 3;
                return Ok(());
            } else {
                el.kids.push(self.element()?);
            }
        }
    }
}

/// Decode the predefined entities and character references.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest.find(';').and_then(|e| {
            let c = match &rest[1..e] {
                "lt" => '<',
                "gt" => '>',
                "amp" => '&',
                "quot" => '"',
                "apos" => '\'',
                n => {
                    let code = match n.strip_prefix("#x") {
                        Some(h) => u32::from_str_radix(h, 16).ok(),
                        None => n.strip_prefix('#').and_then(|d| d.parse().ok()),
                    };
                    char::from_u32(code?)?
                }
            };
            Some((c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_attributes_text() {
        let doc = r#"<?xml version="1.0"?>
<!-- c --><a x="1" y='a&amp;b'><b/><!-- c --><c n="0x10">t &lt;<![CDATA[ * ESP = 4; ]]></c></a>"#;
        let a = parse(doc).unwrap();
        assert_eq!(a.name, "a");
        assert_eq!(a.attr("y"), Some("a&b"));
        assert_eq!(a.kids.len(), 2);
        let c = a.kid("c").unwrap();
        assert_eq!(c.int("n").unwrap(), 16);
        assert_eq!(c.text, "t < * ESP = 4; ");
    }

    #[test]
    fn errors() {
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a x=1/>").is_err());
        assert!(parse("<a>").is_err());
    }
}
