//! `AsRegistry` — in-memory map of registered Application Services,
//! kept in sync with RocksDB. All admin operations go through here.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use thiserror::Error;

use vela_store::db::Database;

use crate::appservice::namespace::{NamespaceError, NamespaceMatcher};
use crate::appservice::{AppService, Namespace};

#[derive(Clone)]
pub struct LiveAppService {
    pub appservice: AppService,
    pub matcher: Arc<NamespaceMatcher>,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("namespace compile failed: {0}")]
    Namespace(#[from] NamespaceError),
    #[error("appservice id already registered: {0}")]
    DuplicateId(String),
    #[error("namespace `{regex}` overlaps exclusive claim from `{by}`")]
    NamespaceConflict { regex: String, by: String },
    #[error("nid lookup failed: {0}")]
    NidLookup(String),
}

impl From<rocksdb::Error> for RegistryError {
    fn from(e: rocksdb::Error) -> Self {
        RegistryError::Storage(e.to_string())
    }
}

pub struct AsRegistry {
    db: Arc<Database>,
    by_nid: DashMap<u64, LiveAppService>,
    by_id: DashMap<String, u64>,
    /// SHA-256-hash → nid index over `as_token`. Lets the auth
    /// middleware resolve an inbound `Bearer <as_token>` in O(1).
    by_as_token_hash: DashMap<String, u64>,
}

impl AsRegistry {
    pub fn open(db: Arc<Database>) -> Result<Self, RegistryError> {
        let by_nid = DashMap::new();
        let by_id = DashMap::new();
        let by_as_token_hash = DashMap::new();
        for (nid, value) in db.iter_appservices()? {
            let asv = AppService::from_value(&value)
                .map_err(|e| RegistryError::Storage(e.to_string()))?;
            let matcher = Arc::new(NamespaceMatcher::compile(&asv.namespaces)?);
            by_id.insert(asv.id.clone(), nid);
            by_as_token_hash.insert(asv.config.as_token_hash.clone(), nid);
            by_nid.insert(
                nid,
                LiveAppService {
                    appservice: asv,
                    matcher,
                },
            );
        }
        Ok(Self {
            db,
            by_nid,
            by_id,
            by_as_token_hash,
        })
    }

    /// Register a new AS. Caller hands in the AppService produced by
    /// `registration::parse`; the registry allocates the nid,
    /// validates conflicts, persists, updates indices.
    pub fn register(&self, mut asv: AppService) -> Result<AppService, RegistryError> {
        if self.by_id.contains_key(&asv.id) {
            return Err(RegistryError::DuplicateId(asv.id));
        }
        for ns in &asv.namespaces {
            if let Some(by) = self.find_exclusive_conflict(ns) {
                return Err(RegistryError::NamespaceConflict {
                    regex: ns.regex.clone(),
                    by,
                });
            }
        }
        let matcher = Arc::new(NamespaceMatcher::compile(&asv.namespaces)?);
        let nid = self
            .db
            .get_or_create_nid(&format!("as:{}", asv.id))
            .map_err(|e| RegistryError::NidLookup(e.to_string()))?;
        asv.nid = nid;
        asv.created_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.db.put_appservice(nid, &asv.to_value())?;
        self.by_id.insert(asv.id.clone(), nid);
        self.by_as_token_hash
            .insert(asv.config.as_token_hash.clone(), nid);
        self.by_nid.insert(
            nid,
            LiveAppService {
                appservice: asv.clone(),
                matcher,
            },
        );
        Ok(asv)
    }

    pub fn unregister(&self, nid: u64) -> Result<bool, RegistryError> {
        let removed = self.by_nid.remove(&nid);
        if let Some((_, live)) = removed {
            self.by_id.remove(&live.appservice.id);
            self.by_as_token_hash
                .remove(&live.appservice.config.as_token_hash);
            self.db.delete_appservice(nid)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn set_enabled(&self, nid: u64, enabled: bool) -> Result<bool, RegistryError> {
        let mut entry = match self.by_nid.get_mut(&nid) {
            Some(e) => e,
            None => return Ok(false),
        };
        if entry.appservice.enabled == enabled {
            return Ok(true);
        }
        entry.appservice.enabled = enabled;
        self.db.put_appservice(nid, &entry.appservice.to_value())?;
        Ok(true)
    }

    pub fn get(&self, nid: u64) -> Option<LiveAppService> {
        self.by_nid.get(&nid).map(|e| e.value().clone())
    }

    pub fn get_by_id(&self, id: &str) -> Option<LiveAppService> {
        let nid = self.by_id.get(id).map(|r| *r.value())?;
        self.get(nid)
    }

    /// Resolve an inbound `Bearer <as_token>` to its AS, if any. The
    /// caller hashes the cleartext token; we look up the hash.
    pub fn get_by_as_token_hash(&self, hash: &str) -> Option<LiveAppService> {
        let nid = self.by_as_token_hash.get(hash).map(|r| *r.value())?;
        self.get(nid)
    }

    pub fn list(&self) -> Vec<LiveAppService> {
        self.by_nid.iter().map(|e| e.value().clone()).collect()
    }

    fn find_exclusive_conflict(&self, candidate: &Namespace) -> Option<String> {
        if !candidate.exclusive {
            return None;
        }
        for entry in self.by_nid.iter() {
            let live = entry.value();
            for ns in &live.appservice.namespaces {
                if ns.exclusive && ns.scope == candidate.scope && ns.regex == candidate.regex {
                    return Some(live.appservice.id.clone());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appservice::AppServiceConfig;
    use crate::appservice::namespace::NamespaceScope;
    use crate::test_helpers::build_test_state;

    fn make(id: &str, namespaces: Vec<Namespace>) -> AppService {
        AppService {
            nid: 0,
            id: id.into(),
            config: AppServiceConfig {
                url: "http://localhost".into(),
                hs_token_hash: format!("hs-{id}"),
                as_token_hash: format!("as-{id}"),
                sender_localpart: "_bot".into(),
                receive_ephemeral: false,
            },
            namespaces,
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        }
    }

    fn ns(scope: NamespaceScope, regex: &str, exclusive: bool) -> Namespace {
        Namespace {
            scope,
            regex: regex.into(),
            exclusive,
        }
    }

    #[test]
    fn register_unregister_roundtrip() {
        let (state, _tmp) = build_test_state();
        let reg = AsRegistry::open(state.db.clone()).unwrap();
        let asv = reg.register(make("alpha", vec![])).unwrap();
        assert_eq!(reg.list().len(), 1);
        assert!(reg.get(asv.nid).is_some());
        assert!(reg.get_by_id("alpha").is_some());
        assert!(reg.get_by_as_token_hash("as-alpha").is_some());

        let reg2 = AsRegistry::open(state.db.clone()).unwrap();
        assert!(reg2.get_by_id("alpha").is_some());

        assert!(reg2.unregister(asv.nid).unwrap());
        let reg3 = AsRegistry::open(state.db.clone()).unwrap();
        assert!(reg3.get_by_id("alpha").is_none());
    }

    #[test]
    fn duplicate_id_refused() {
        let (state, _tmp) = build_test_state();
        let reg = AsRegistry::open(state.db.clone()).unwrap();
        reg.register(make("dup", vec![])).unwrap();
        let err = reg.register(make("dup", vec![])).unwrap_err();
        assert!(matches!(err, RegistryError::DuplicateId(_)));
    }

    #[test]
    fn exclusive_namespace_conflict_refused() {
        let (state, _tmp) = build_test_state();
        let reg = AsRegistry::open(state.db.clone()).unwrap();
        reg.register(make(
            "first",
            vec![ns(NamespaceScope::User, r"^@_irc_.*", true)],
        ))
        .unwrap();
        let err = reg
            .register(make(
                "second",
                vec![ns(NamespaceScope::User, r"^@_irc_.*", true)],
            ))
            .unwrap_err();
        assert!(matches!(err, RegistryError::NamespaceConflict { .. }));
    }

    #[test]
    fn set_enabled_persists() {
        let (state, _tmp) = build_test_state();
        let reg = AsRegistry::open(state.db.clone()).unwrap();
        let asv = reg.register(make("x", vec![])).unwrap();
        assert!(reg.set_enabled(asv.nid, false).unwrap());
        let reg2 = AsRegistry::open(state.db.clone()).unwrap();
        assert!(!reg2.get(asv.nid).unwrap().appservice.enabled);
    }
}
