//! Binary key encoding helpers for RocksDB composite keys.
//! All integers use big-endian encoding for correct byte ordering.

/// Encode a single u64 as 8 big-endian bytes.
pub fn encode_u64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Decode a u64 from 8 big-endian bytes.
pub fn decode_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(buf)
}

/// Encode a (u64, u64) composite key as 16 bytes.
pub fn encode_u64_pair(a: u64, b: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&a.to_be_bytes());
    key[8..16].copy_from_slice(&b.to_be_bytes());
    key
}

/// Decode a (u64, u64) pair from 16 bytes.
pub fn decode_u64_pair(bytes: &[u8]) -> (u64, u64) {
    (decode_u64(&bytes[0..8]), decode_u64(&bytes[8..16]))
}

/// Encode a (u64, u64, u64) composite key as 24 bytes.
pub fn encode_u64_triple(a: u64, b: u64, c: u64) -> [u8; 24] {
    let mut key = [0u8; 24];
    key[0..8].copy_from_slice(&a.to_be_bytes());
    key[8..16].copy_from_slice(&b.to_be_bytes());
    key[16..24].copy_from_slice(&c.to_be_bytes());
    key
}

/// Encode a (u64, bytes) composite key. Used for (user_nid, device_id) etc.
pub fn encode_u64_bytes(nid: u64, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + suffix.len());
    key.extend_from_slice(&nid.to_be_bytes());
    key.extend_from_slice(suffix);
    key
}

/// Encode a (u64, u64, bytes) composite key. Used for thread
/// subscriptions: (user_nid, room_nid, thread_root_event_id).
pub fn encode_u64_pair_bytes(n1: u64, n2: u64, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(16 + suffix.len());
    key.extend_from_slice(&n1.to_be_bytes());
    key.extend_from_slice(&n2.to_be_bytes());
    key.extend_from_slice(suffix);
    key
}

/// Encode a (u64, bytes, bytes) composite key. Used for (user_nid, device_id, txn_id).
pub fn encode_u64_bytes_bytes(nid: u64, b1: &[u8], b2: &[u8]) -> Vec<u8> {
    // Use a length prefix for b1 so we can distinguish the boundary
    let len = b1.len() as u16;
    let mut key = Vec::with_capacity(8 + 2 + b1.len() + b2.len());
    key.extend_from_slice(&nid.to_be_bytes());
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(b1);
    key.extend_from_slice(b2);
    key
}

/// Encode a packed array of u64 values.
pub fn encode_u64_array(values: &[u64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(values.len() * 8);
    for &v in values {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf
}

/// Decode a packed array of u64 values.
pub fn decode_u64_array(bytes: &[u8]) -> Vec<u64> {
    let (chunks, _remainder) = bytes.as_chunks::<8>();
    chunks.iter().map(|c| decode_u64(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_roundtrip() {
        assert_eq!(decode_u64(&encode_u64(12345)), 12345);
        assert_eq!(decode_u64(&encode_u64(0)), 0);
        assert_eq!(decode_u64(&encode_u64(u64::MAX)), u64::MAX);
    }

    #[test]
    fn u64_pair_ordering() {
        // Big-endian ensures (1, 100) < (2, 0) in byte order
        let a = encode_u64_pair(1, 100);
        let b = encode_u64_pair(2, 0);
        assert!(a < b);

        // Same first element: ordered by second
        let c = encode_u64_pair(1, 50);
        let d = encode_u64_pair(1, 100);
        assert!(c < d);
    }

    #[test]
    fn u64_array_roundtrip() {
        let vals = vec![1, 2, 3, 42, u64::MAX];
        assert_eq!(decode_u64_array(&encode_u64_array(&vals)), vals);
        assert_eq!(decode_u64_array(&encode_u64_array(&[])), Vec::<u64>::new());
    }
}
