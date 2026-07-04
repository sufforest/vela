//! Full-text search tokenizer.
//!
//! The tokenizer is the load-bearing piece for CJK search: it wraps jieba
//! word segmentation so Chinese/Japanese text — written without spaces —
//! yields real word tokens (你好世界 → 你好 / 世界) instead of one giant
//! unmatchable token (the failure mode in Synapse and conduwuit).
//!
//! The SAME function must run at index time and query time or nothing
//! matches, so it lives in the store, shared by the write path
//! (`Database::persist_event_kind`) and the query path (vela-api's
//! `/search` handler via `Database`).

use std::collections::HashMap;
use std::sync::OnceLock;

use jieba_rs::Jieba;
use serde_json::Value;

/// Key separator between the variable-length token and the fixed 8-byte
/// stream-position suffix. `0xFF` is never a byte in valid UTF-8, so a
/// token can never contain it — the delimiter is unambiguous, and the
/// prefix `room ++ token ++ 0xFF` matches only that exact token (never a
/// longer token that happens to share a prefix).
pub const SEP: u8 = 0xFF;

/// Field tags stored in the index value (which of the searchable CS-API
/// keys this posting came from), so a query can honor the `keys` filter.
pub const FIELD_BODY: u8 = 0;
pub const FIELD_NAME: u8 = 1;
pub const FIELD_TOPIC: u8 = 2;

/// One hit for a (room, token): where it is and how strongly it matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Posting {
    pub stream_pos: u64,
    pub event_nid: u64,
    pub field: u8,
    /// Term frequency in the event (capped at 255); summed into `rank`.
    pub tf: u8,
}

/// `search_index` key: `room_nid ++ token ++ 0xFF ++ stream_pos`.
pub fn index_key(room_nid: u64, token: &str, stream_pos: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + token.len() + 1 + 8);
    k.extend_from_slice(&room_nid.to_be_bytes());
    k.extend_from_slice(token.as_bytes());
    k.push(SEP);
    k.extend_from_slice(&stream_pos.to_be_bytes());
    k
}

/// Prefix selecting every posting for (room, token): `room ++ token ++ 0xFF`.
pub fn token_prefix(room_nid: u64, token: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + token.len() + 1);
    p.extend_from_slice(&room_nid.to_be_bytes());
    p.extend_from_slice(token.as_bytes());
    p.push(SEP);
    p
}

/// `search_index` value: `event_nid ++ field ++ tf`.
pub fn encode_value(event_nid: u64, field: u8, tf: u8) -> [u8; 10] {
    let mut v = [0u8; 10];
    v[..8].copy_from_slice(&event_nid.to_be_bytes());
    v[8] = field;
    v[9] = tf;
    v
}

/// Decode a `search_index` value into `(event_nid, field, tf)`.
pub fn decode_value(v: &[u8]) -> Option<(u64, u8, u8)> {
    if v.len() < 10 {
        return None;
    }
    let event_nid = u64::from_be_bytes(v[..8].try_into().ok()?);
    Some((event_nid, v[8], v[9]))
}

/// The trailing 8-byte stream position of a `search_index` key.
pub fn key_stream_pos(key: &[u8]) -> Option<u64> {
    if key.len() < 8 {
        return None;
    }
    Some(u64::from_be_bytes(key[key.len() - 8..].try_into().ok()?))
}

/// The searchable text of an event and which CS-API key it is, or `None`
/// when the event carries nothing searchable. Mirrors the spec's supported
/// keys: `content.body` (m.room.message), `content.name` (m.room.name),
/// `content.topic` plus the `text/plain` body of the extensible
/// `content['m.topic']` (m.room.topic).
pub fn searchable_field(event_json: &Value) -> Option<(u8, String)> {
    let ty = event_json.get("type")?.as_str()?;
    let content = event_json.get("content")?;
    match ty {
        "m.room.message" => content
            .get("body")
            .and_then(Value::as_str)
            .filter(|b| !b.is_empty())
            .map(|b| (FIELD_BODY, b.to_string())),
        "m.room.name" => content
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .map(|n| (FIELD_NAME, n.to_string())),
        "m.room.topic" => {
            let mut text = content
                .get("topic")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            // Fold in the text/plain representation of MSC3765 m.topic.
            if let Some(reps) = content
                .get("m.topic")
                .and_then(|t| t.get("m.text"))
                .and_then(Value::as_array)
            {
                for rep in reps {
                    let mimetype = rep
                        .get("mimetype")
                        .and_then(Value::as_str)
                        .unwrap_or("text/plain");
                    if mimetype == "text/plain"
                        && let Some(b) = rep.get("body").and_then(Value::as_str)
                        && !text.contains(b)
                    {
                        if !text.is_empty() {
                            text.push(' ');
                        }
                        text.push_str(b);
                    }
                }
            }
            (!text.trim().is_empty()).then_some((FIELD_TOPIC, text))
        }
        _ => None,
    }
}

/// Cap on an indexed token's UTF-8 length. Bounds search-index key size;
/// longer runs (URLs, base64 blobs, pathological input) are dropped from
/// the index rather than bloating it. Query tokens over the cap likewise
/// never match — acceptable, since real words are far shorter.
pub const TOKEN_MAX_BYTES: usize = 60;

/// Process-wide jieba instance. `Jieba::new` parses the embedded dictionary
/// (~tens of ms, tens of MB resident), so build it once and lazily — a
/// server with search disabled never pays for it.
fn jieba() -> &'static Jieba {
    static JIEBA: OnceLock<Jieba> = OnceLock::new();
    JIEBA.get_or_init(Jieba::new)
}

/// Force the jieba dictionary to load now. Called once at boot (off the
/// request path) when search is enabled, so the first indexed message
/// doesn't pay the one-time dictionary-load latency inline on a persist.
pub fn warm() {
    let _ = jieba();
}

/// Split `text` into lowercased search tokens.
///
/// jieba `cut_for_search` segments CJK into words (and further splits long
/// words, which improves recall) while passing Latin runs through on
/// whitespace/punctuation boundaries. Segments with no alphanumeric
/// character (punctuation, whitespace) and tokens over [`TOKEN_MAX_BYTES`]
/// are dropped. Deterministic and identical at index and query time.
///
/// Duplicates are preserved so the caller can count term frequency; use
/// [`token_frequencies`] when you want the aggregated form.
pub fn tokenize(text: &str) -> Vec<String> {
    jieba()
        .cut_for_search(text, true)
        .into_iter()
        .map(|tok| tok.word)
        .filter(|seg| seg.chars().any(char::is_alphanumeric))
        .map(str::to_lowercase)
        .filter(|tok| tok.len() <= TOKEN_MAX_BYTES)
        .collect()
}

/// Tokenize `text` and count how often each distinct token appears. The
/// count is the term frequency stored in the inverted index and summed
/// into the relevance `rank`.
pub fn token_frequencies(text: &str) -> HashMap<String, u32> {
    let mut freq: HashMap<String, u32> = HashMap::new();
    for tok in tokenize(text) {
        *freq.entry(tok).or_insert(0) += 1;
    }
    freq
}

/// The distinct query tokens for `search_term`, deduplicated (order not
/// significant — the query intersects postings across them).
pub fn query_tokens(search_term: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    tokenize(search_term)
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_is_segmented_into_words() {
        // The whole point: a space-less Chinese run must become real word
        // tokens, not one unmatchable blob.
        let toks = tokenize("你好世界");
        assert!(toks.contains(&"你好".to_string()), "got {toks:?}");
        assert!(toks.contains(&"世界".to_string()), "got {toks:?}");
        // And a query for one of the words tokenizes to that same word, so
        // it will match the indexed document.
        assert!(query_tokens("世界").contains(&"世界".to_string()));
    }

    #[test]
    fn mixed_cjk_and_latin() {
        let toks = tokenize("hello 世界 Rust");
        assert!(toks.contains(&"hello".to_string()), "got {toks:?}");
        assert!(toks.contains(&"世界".to_string()), "got {toks:?}");
        // Latin is lowercased.
        assert!(toks.contains(&"rust".to_string()), "got {toks:?}");
    }

    #[test]
    fn latin_lowercased_and_punctuation_dropped() {
        let toks = tokenize("Hello, WORLD! foo-bar.");
        assert!(toks.contains(&"hello".to_string()), "got {toks:?}");
        assert!(toks.contains(&"world".to_string()), "got {toks:?}");
        // No pure-punctuation tokens survive.
        assert!(toks.iter().all(|t| t.chars().any(char::is_alphanumeric)));
    }

    #[test]
    fn over_long_tokens_dropped() {
        let long = "a".repeat(TOKEN_MAX_BYTES + 1);
        assert!(tokenize(&long).is_empty(), "over-cap token must be dropped");
        let ok = "a".repeat(TOKEN_MAX_BYTES);
        assert_eq!(tokenize(&ok), vec![ok]);
    }

    #[test]
    fn term_frequency_counts_repeats() {
        let freq = token_frequencies("cat cat dog");
        assert_eq!(freq.get("cat"), Some(&2));
        assert_eq!(freq.get("dog"), Some(&1));
    }

    #[test]
    fn query_tokens_are_deduped() {
        let q = query_tokens("cat cat cat");
        assert_eq!(q, vec!["cat".to_string()]);
    }

    #[test]
    fn empty_and_whitespace_yield_no_tokens() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   \n\t  ").is_empty());
        assert!(tokenize("!!! ??? ...").is_empty());
    }
}
