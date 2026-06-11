//! End-to-end encryption surface. Device keys (incl. cross-signing),
//! one-time keys, key backup (room-key recovery), and to-device
//! delivery. The federation-side device-key query handler also lives
//! here because it's pure e2ee plumbing.

pub mod dehydrated_devices;
pub mod federation_devices;
pub mod key_backup;
pub mod keys;
pub mod to_device;
