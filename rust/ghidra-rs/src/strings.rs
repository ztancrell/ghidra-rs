//! Ghidra's "ASCII Strings" analyzer with its defaults: the search of `StringSearcher`
//! (`MinLengthCharSequenceMatcher`, `MultiByteCharMatcher`: ASCII and UTF-16 strings of 5 or
//! more characters with a terminator) and the test of `StringsAnalyzer.createStringIfValid`,
//! which keeps a string whose trigram score (`NGramUtils`, `StringAndScores`) is above the
//! threshold of its length. The model is Ghidra's file
//! `Ghidra/Features/Base/data/stringngrams/StringModel.sng`.

const N: usize = 128;

/// `NGramUtils.NG_THRESHOLDS`, by the length of the scored string; `MAX_NG_THRESHOLD` past it.
const THRESHOLDS: [f64; 101] = [
    10.0, 10.0, 10.0, 10.0, -2.71, -3.26, -3.52, -3.84, -4.23, -4.49, //
    -4.55, -4.74, -4.88, -5.03, -5.06, -5.2, -5.24, -5.29, -5.29, -5.42, //
    -5.51, -5.52, -5.53, -5.6, -5.6, -5.62, -5.7, -5.7, -5.78, -5.79, //
    -5.81, -5.81, -5.84, -5.85, -5.86, -5.88, -5.92, -5.92, -5.93, -5.95, //
    -5.99, -6.0, -6.0, -6.0, -6.02, -6.02, -6.02, -6.05, -6.06, -6.07, //
    -6.08, -6.1, -6.12, -6.12, -6.13, -6.13, -6.13, -6.13, -6.13, -6.13, //
    -6.13, -6.15, -6.15, -6.16, -6.16, -6.16, -6.17, -6.19, -6.19, -6.21, //
    -6.21, -6.21, -6.21, -6.21, -6.21, -6.25, -6.25, -6.25, -6.25, -6.25, //
    -6.25, -6.25, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, //
    -6.26, -6.29, -6.29, -6.3, -6.3, -6.3, -6.3, -6.3, -6.3, -6.3, -6.3,
];
const MAX_THRESHOLD: f64 = -6.3;

/// `StringsAnalyzer`'s default "Minimum String Length"
pub const MIN_LENGTH: i64 = 5;
/// `StringsAnalyzer`'s default "String end alignment"
pub const END_ALIGNMENT: u32 = 4;

/// The log probabilities of a trigram model file (`NGramUtils.ingestModel`,
/// `smoothCountsAndCalculateLogProbs`).
pub struct Model {
    begin: Vec<f64>,
    end: Vec<f64>,
    tri: Vec<f64>,
    lowercase: bool,
}

impl Model {
    pub fn parse(text: &str) -> Result<Model, String> {
        // `convertToAsciiNums`: one character, or a description in brackets
        enum Sym {
            Begin,
            End,
            Char(usize),
        }
        fn sym(s: &str) -> Result<Sym, String> {
            const NAMES: [&str; 33] = [
                "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL", "BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI",
                "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB", "CAN", "EM", "SUB", "ESC", "FS", "GS", "RS",
                "US", "SP",
            ];
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if (c as usize) < N => Ok(Sym::Char(c as usize)),
                _ if s == "[^]" => Ok(Sym::Begin),
                _ if s == "[$]" => Ok(Sym::End),
                _ if s == "[DEL]" => Ok(Sym::Char(127)),
                _ => s
                    .strip_prefix('[')
                    .and_then(|x| x.strip_suffix(']'))
                    .and_then(|x| NAMES.iter().position(|n| *n == x))
                    .map(Sym::Char)
                    .ok_or_else(|| format!("cannot parse the character {s}")),
            }
        }
        let (mut begin, mut end, mut tri) = (vec![0u64; N * N], vec![0u64; N * N], vec![0u64; N * N * N]);
        let (mut total, mut kind) = (0u64, None);
        for line in text.lines() {
            if line.starts_with('#') {
                if let Some(at) = line.find("Model Type: ") {
                    kind = Some(line[at + "Model Type: ".len()..].to_string());
                }
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            let [a, b, c, count] = parts[..] else { return Err(format!("not 4 parts: {line}")) };
            let count: u64 = count.parse().map_err(|_| format!("bad count: {line}"))?;
            match (sym(a)?, sym(b)?, sym(c)?) {
                (Sym::Begin, Sym::Char(x), Sym::Char(y)) => begin[x * N + y] += count,
                (Sym::Begin, _, _) => {}
                (Sym::Char(x), Sym::Char(y), Sym::End) => end[x * N + y] += count,
                (Sym::Char(x), Sym::Char(y), Sym::Char(z)) => tri[(x * N + y) * N + z] += count,
                _ => return Err(format!("bad trigram: {line}")),
            }
            total += count;
        }
        let kind = kind.ok_or("the model file does not contain the model type")?;
        // a count of 0 becomes 1
        total += begin.iter().chain(&end).chain(&tri).filter(|&&c| c == 0).count() as u64;
        let logs = |v: Vec<u64>| v.into_iter().map(|c| (c.max(1) as f64 / total as f64).log10()).collect();
        Ok(Model {
            begin: logs(begin),
            end: logs(end),
            tri: logs(tri),
            lowercase: kind.eq_ignore_ascii_case("lowercase"),
        })
    }

    /// `createStringIfValid`'s test of the characters before the terminator: `StringAndScores`
    /// (lower case for a lower-case model, trimmed, runs of spaces and of tabs as one),
    /// `NGramUtils.scoreString`, `isScoreAboveThreshold`.
    pub fn accepts(&self, chars: &[u8]) -> bool {
        let lower = |c: u8| if self.lowercase { c.to_ascii_lowercase() } else { c };
        let first = chars.iter().position(|&c| c > b' ').unwrap_or(chars.len());
        let last = chars.iter().rposition(|&c| c > b' ').map_or(first, |p| p + 1);
        let mut s: Vec<usize> = Vec::with_capacity(last - first);
        for &c in &chars[first..last] {
            if (c == b' ' || c == b'\t') && s.last() == Some(&(c as usize)) {
                continue;
            }
            s.push(lower(c) as usize & (N - 1));
        }
        let n = s.len();
        // 3 is `ABSOLUTE_MIN_STR_LENGTH` (read before the first model is loaded); no string of
        // fewer than 4 characters passes its threshold
        if n < 3 {
            return false;
        }
        let mut sum = self.begin[s[0] * N + s[1]];
        for i in 1..=n - 3 {
            sum += self.tri[(s[i] * N + s[i + 1]) * N + s[i + 2]];
        }
        sum += self.end[s[n - 2] * N + s[n - 1]];
        sum / n as f64 > THRESHOLDS.get(n).copied().unwrap_or(MAX_THRESHOLD)
    }
}

/// `AsciiCharSetRecognizer`
fn printable(c: u32) -> bool {
    (0x20..=0x7e).contains(&c) || matches!(c, 9 | 10 | 13)
}

/// `MinLengthCharSequenceMatcher` with alignment 1, where only a terminated sequence counts
/// (`StringSearcher` with "Require Null Termination").
#[derive(Default)]
struct Matcher {
    start: i64,
    index: i64,
    inside: bool,
}

impl Matcher {
    /// The character indexes of a sequence that `c` ends: its first character and its
    /// terminator.
    fn add(&mut self, c: u32) -> Option<(i64, i64)> {
        let at = self.index;
        self.index += 1;
        if printable(c) {
            if !self.inside {
                (self.start, self.inside) = (at, true);
            }
            return None;
        }
        let was = std::mem::take(&mut self.inside);
        (was && c == 0 && at - self.start >= MIN_LENGTH).then_some((self.start, at))
    }
}

/// A string the search finds: its first byte, its bytes with the terminator, UTF-16 or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    pub offset: usize,
    pub len: usize,
    pub wide: bool,
}

/// `AbstractStringSearcher.searchRange` over one range of memory: the ASCII matcher and the
/// UTF-16 matchers at both byte offsets, each asked at every byte in that order.
pub fn search(bytes: &[u8], found: &mut dyn FnMut(Found)) {
    let (mut ascii, mut wide) = (Matcher::default(), [Matcher::default(), Matcher::default()]);
    for (i, &b) in bytes.iter().enumerate() {
        if let Some((s, e)) = ascii.add(b as u32) {
            found(Found { offset: s as usize, len: (e - s + 1) as usize, wide: false });
        }
        for (off, m) in wide.iter_mut().enumerate() {
            // the second byte of a character at this offset
            if i > off && (i - off) % 2 == 1 {
                let c = u16::from_le_bytes([bytes[i - 1], b]) as u32;
                if let Some((s, e)) = m.add(c) {
                    found(Found { offset: s as usize * 2 + off, len: (e - s + 1) as usize * 2, wide: true });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_finds_terminated_strings_of_five() {
        let mut bytes = b"\x01hello\0abcd\0wxyz!".to_vec();
        bytes.extend(b"\0\0w\0i\0d\0e\0s\0\0\0");
        let mut out = Vec::new();
        search(&bytes, &mut |f| out.push(f));
        // "abcd" is too short, "wxyz!" is terminated, the UTF-16 string starts at an even offset
        assert_eq!(
            out,
            [
                Found { offset: 1, len: 6, wide: false },
                Found { offset: 12, len: 6, wide: false },
                Found { offset: 19, len: 12, wide: true }
            ]
        );
    }

    #[test]
    fn model_scores_as_ngramutils() {
        // two trigrams, a begin and an end pair; every other count is smoothed to 1
        let text =
            "# Model Type: lowercase\n[^]\ta\tb\t1000000\na\tb\tc\t1000000\nb\tc\td\t1000000\nc\td\t[$]\t1000000\n";
        let m = Model::parse(text).unwrap();
        let total = 4_000_000.0 + (2 * N * N + N * N * N - 4) as f64;
        assert!((m.begin[b'a' as usize * N + b'b' as usize] - (1e6 / total).log10()).abs() < 1e-12);
        // "ABCD": begin(a,b) + tri(b,c,d) + end(c,d) over 4, far above -2.71; the first trigram is not read
        assert!(m.accepts(b"  ABCD "));
        assert!(!m.accepts(b"zqxj"));
        assert!(!m.accepts(b"abc"));
        assert!(Model::parse("a\tb\tc\t1\n").is_err());
    }
}
