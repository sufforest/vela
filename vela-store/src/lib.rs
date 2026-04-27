pub mod cf;
pub mod db;
pub mod keys;
pub mod media;
pub mod nid;
pub mod store;

// Re-exports so the trait is reachable without the `store::` path.
pub use store::{MatrixStore, StoreError, StoreResult};
