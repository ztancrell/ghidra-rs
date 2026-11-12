//! A small XML reader (the part of Ghidra's `xml.y` + `XmlDecode` ghidra-rs needs) for the
//! `.pspec`/`.cspec` files and the decompiler datatests: elements, attributes, character data
//! (entities and CDATA decoded). Comments, the `<?xml?>` declaration and `<!DOCTYPE>` are
//! skipped. A character reference below 256 (`&#xc2;`) is one byte, as Ghidra's reader takes
//! it; text that is then not UTF-8 is converted lossily.

/// Errors are messages with the line number.
pub(crate) type Result<T> = std::result::Result<T, String>;

/// How deep elements may nest: a bound on the recursion for hostile input.
const MAX_DEPTH: usize = 256;

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
        self.attr(name).ok_or_else(|| format!("<{}>: missing attribute {name}", self.name))
    }

    /// The attribute `name` as an integer (decimal, `0x` hex, or negative decimal), as
    /// `Decoder::readSignedInteger` reads it.
    pub(crate) fn int(&self, name: &str) -> Result<i64> {
        parse_int(self.req(name)?).ok_or_else(|| format!("<{}>: bad integer in {name}", self.name))
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

    /// The first element named `name` at any depth below this one, in document order.
    pub(crate) fn find(&self, name: &str) -> Option<&Element> {
        self.kids.iter().find_map(|k| if k.name == name { Some(k) } else { k.find(name) })
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
    let mut p = Parser { s: text, pos: 0, depth: 0 };
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
    /// elements open around the current position
    depth: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn fail<T>(&self, what: &str) -> Result<T> {
        let line = self.s[..self.pos].matches('\n').count() + 1;
        Err(format!("XML line {line}: {what}"))
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
        if self.depth >= MAX_DEPTH {
            return self.fail("elements nested too deeply");
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
        self.depth += 1;
        let res = self.content(&mut el);
        self.depth -= 1;
        res.map(|()| el)
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
                let Some(end) = close.find('>') else { return self.fail("unterminated end tag") };
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

/// Decode the predefined entities and character references (below 256: one byte).
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.extend_from_slice(&rest.as_bytes()[..i]);
        rest = &rest[i..];
        let decoded = rest.find(';').and_then(|e| {
            let code = match &rest[1..e] {
                "lt" => u32::from(b'<'),
                "gt" => u32::from(b'>'),
                "amp" => u32::from(b'&'),
                "quot" => u32::from(b'"'),
                "apos" => u32::from(b'\''),
                n => match n.strip_prefix("#x") {
                    Some(h) => u32::from_str_radix(h, 16).ok()?,
                    None => n.strip_prefix('#')?.parse().ok()?,
                },
            };
            Some((code, e + 1))
        });
        match decoded {
            Some((code, len)) => {
                match u8::try_from(code) {
                    Ok(b) => out.push(b),
                    Err(_) => out.extend_from_slice(char::from_u32(code).unwrap_or('\u{fffd}').to_string().as_bytes()),
                }
                rest = &rest[len..];
            }
            None => {
                out.push(b'&');
                rest = &rest[1..];
            }
        }
    }
    out.extend_from_slice(rest.as_bytes());
    String::from_utf8_lossy(&out).into_owned()
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
        assert_eq!(parse("<a><b><c/></b></a>").unwrap().find("c").map(|c| c.name.as_str()), Some("c"));
    }

    #[test]
    fn errors() {
        for bad in ["<a><b></a>", "<a x=1/>", "<a>", "<a></a", "<a><!-- x"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let deep = "<a>".repeat(MAX_DEPTH + 1);
        assert!(parse(&deep).unwrap_err().contains("too deeply"));
    }
}
