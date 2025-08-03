use crate::core::config::AppConfig;
use crate::core::error::WafError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub version: u64,
    pub config: AppConfig,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigExport {
    pub version: u64,
    pub config: AppConfig,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub checksum: String,
}

impl ConfigVersion {
    pub fn new(version: u64, config: AppConfig, description: String) -> Self {
        let timestamp = Utc::now();
        let checksum = Self::calculate_checksum(&config);

        Self {
            version,
            config,
            description,
            timestamp,
            checksum,
        }
    }

    fn calculate_checksum(config: &AppConfig) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let serialized = serde_json::to_string(config).unwrap_or_default();
        let mut hasher = DefaultHasher::new();
        serialized.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[derive(Debug)]
pub struct ConfigStorage {
    versions: Arc<RwLock<HashMap<u64, ConfigVersion>>>,
    current_version: Arc<RwLock<u64>>,
    max_versions: usize,
    next_version: Arc<RwLock<u64>>,
}

impl ConfigStorage {
    pub fn new(max_versions: usize) -> Self {
        Self {
            versions: Arc::new(RwLock::new(HashMap::new())),
            current_version: Arc::new(RwLock::new(0)),
            max_versions,
            next_version: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn store_config(
        &self,
        config: AppConfig,
        description: String,
    ) -> Result<u64, WafError> {
        let mut next_version = self.next_version.write().await;
        let version = *next_version;
        *next_version += 1;
        drop(next_version);

        let config_version = ConfigVersion::new(version, config, description);

        let mut versions = self.versions.write().await;
        versions.insert(version, config_version);

        if versions.len() > self.max_versions {
            let oldest_version = versions.keys().min().copied();
            if let Some(oldest) = oldest_version {
                versions.remove(&oldest);
            }
        }

        let mut current_version = self.current_version.write().await;
        *current_version = version;

        Ok(version)
    }

    pub async fn get_current_config(&self) -> Result<Option<AppConfig>, WafError> {
        let current_version = *self.current_version.read().await;
        if current_version == 0 {
            return Ok(None);
        }

        let versions = self.versions.read().await;
        Ok(versions.get(&current_version).map(|v| v.config.clone()))
    }

    pub async fn get_current_version(&self) -> u64 {
        *self.current_version.read().await
    }

    pub async fn get_config_version(
        &self,
        version: u64,
    ) -> Result<Option<ConfigVersion>, WafError> {
        let versions = self.versions.read().await;
        Ok(versions.get(&version).cloned())
    }

    pub async fn list_versions(&self) -> Result<Vec<ConfigVersion>, WafError> {
        let versions = self.versions.read().await;
        let mut version_list: Vec<ConfigVersion> = versions.values().cloned().collect();
        version_list.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(version_list)
    }

    pub async fn restore_version(&self, version: u64) -> Result<(), WafError> {
        let versions = self.versions.read().await;
        if !versions.contains_key(&version) {
            return Err(WafError::Config(format!("Version {} not found", version)));
        }
        drop(versions);

        let mut current_version = self.current_version.write().await;
        *current_version = version;

        Ok(())
    }

    pub async fn export_config(&self, version: Option<u64>) -> Result<ConfigExport, WafError> {
        let target_version = match version {
            Some(v) => v,
            None => self.get_current_version().await,
        };

        let versions = self.versions.read().await;
        let config_version = versions
            .get(&target_version)
            .ok_or_else(|| WafError::Config(format!("Version {} not found", target_version)))?;

        Ok(ConfigExport {
            version: config_version.version,
            config: config_version.config.clone(),
            description: config_version.description.clone(),
            timestamp: config_version.timestamp,
            checksum: config_version.checksum.clone(),
        })
    }

    pub async fn import_config(
        &self,
        export: ConfigExport,
        description: Option<String>,
    ) -> Result<u64, WafError> {
        let desc =
            description.unwrap_or_else(|| format!("Imported from version {}", export.version));
        self.store_config(export.config, desc).await
    }

    pub async fn clear_all_versions(&self) -> Result<(), WafError> {
        let mut versions = self.versions.write().await;
        versions.clear();

        let mut current_version = self.current_version.write().await;
        *current_version = 0;

        let mut next_version = self.next_version.write().await;
        *next_version = 1;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ConfigManager {
    storage: Arc<ConfigStorage>,
    auto_backup: bool,
    backup_interval: u64,
}

impl ConfigManager {
    pub fn new(max_versions: usize, auto_backup: bool, backup_interval: u64) -> Self {
        Self {
            storage: Arc::new(ConfigStorage::new(max_versions)),
            auto_backup,
            backup_interval,
        }
    }

    pub fn get_storage(&self) -> Arc<ConfigStorage> {
        self.storage.clone()
    }

    pub async fn quick_export(&self) -> Result<String, WafError> {
        let export = self.storage.export_config(None).await?;
        serde_json::to_string_pretty(&export)
            .map_err(|e| WafError::Config(format!("Failed to serialize export: {}", e)))
    }

    pub async fn quick_import(&self, data: &str) -> Result<u64, WafError> {
        let export: ConfigExport = serde_json::from_str(data)
            .map_err(|e| WafError::Config(format!("Failed to deserialize import: {}", e)))?;

        self.storage.import_config(export, None).await
    }
}
