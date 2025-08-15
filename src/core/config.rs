use anyhow::{Context, Result};
use config::{Config, File};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub grpc_port: Option<u16>,
    /// worker thread count for the async runtime
    pub worker_threads: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CacheConfig {
    pub max_size: usize,
    pub ttl_seconds: u64,
    pub enabled: bool,
    pub file_cache: Option<FileCacheConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileCacheConfig {
    pub enabled: bool,
    pub cache_dir: String,
    pub prefix: String,
    pub ttl_seconds: u64,
    pub save_interval_seconds: Option<u64>,
    pub max_items: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogConfig {
    pub level: String,
    pub file_path: Option<String>,
    pub prefix: Option<String>,
    pub rotation_policy: Option<String>, // "size:10MB" 或 "time:24h" 或 "never"
    pub compression: Option<bool>,       // 是否压缩
    pub max_files: Option<usize>,        // 最大保留文件数
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RulesConfig {
    pub rules_dir: String,
    pub rule_files: Option<Vec<String>>,
    pub custom_regex_file: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub log: LogConfig,
    #[serde(default)]
    pub rules: RulesConfig,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            rules_dir: "rules".to_string(),
            rule_files: None,
            custom_regex_file: Some("custom_regex.json".to_string()),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                grpc_port: Some(50051),
                worker_threads: None,
            },
            cache: CacheConfig {
                max_size: 10000,
                ttl_seconds: 3600,
                enabled: true,
                file_cache: Some(FileCacheConfig {
                    enabled: false,
                    cache_dir: "cache".to_string(),
                    prefix: "crwaf_cache".to_string(),
                    ttl_seconds: 86400,               // 默认24小时
                    save_interval_seconds: Some(300), // 默认5分钟
                    max_items: Some(1000),            // 默认最多1000项
                }),
            },
            log: LogConfig {
                level: "info".to_string(),
                file_path: None,
                prefix: Some("crwaf".to_string()),
                rotation_policy: Some("time:24h".to_string()),
                compression: Some(false),
                max_files: Some(30),
            },
            rules: RulesConfig::default(),
        }
    }
}

pub fn load_config() -> Result<AppConfig> {
    let config_dir = Path::new("config");
    let config_file = config_dir.join("config.toml");

    // 检查配置文件是否存在
    if !config_file.exists() {
        warn!("配置文件不存在: {:?}, 使用默认配置", config_file);
        return Ok(AppConfig::default());
    }

    let config = Config::builder()
        .add_source(File::from(config_file))
        .build()
        .context("无法加载配置文件")?;

    let app_config: AppConfig = config.try_deserialize().context("无法解析配置文件")?;

    info!("配置加载成功");
    Ok(app_config)
}
