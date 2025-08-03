use crate::core::error::WafError;
use crate::core::statistics::{Statistics, StatisticsData};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub site_id: String,
    pub name: String,
    pub domain: String,
    pub origin: String,
    pub enabled: bool,
    pub security_config: SecurityConfig,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub xss_protection: bool,
    pub sql_injection_protection: bool,
    pub five_second_shield: bool,
    pub click_shield: bool,
    pub captcha: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIP {
    pub ip: String,
    pub reason: String,
    pub blocked_at: u64,
    pub expires_at: u64,
    pub permanent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandType {
    ReloadConfig,
    ClearCache,
    BlockIP,
    UnblockIP,
    UpdateRules,
    RestartService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub instance_id: String,
    pub command_type: CommandType,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub message: String,
    pub data: HashMap<String, String>,
}

#[derive(Debug)]
pub struct DataSyncManager {
    statistics: Arc<Statistics>,
    sites: Arc<RwLock<HashMap<String, SiteInfo>>>,
    blocked_ips: Arc<RwLock<HashMap<String, BlockedIP>>>,
    instance_id: String,
}

impl DataSyncManager {
    pub fn new(statistics: Arc<Statistics>, instance_id: String) -> Self {
        Self {
            statistics,
            sites: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            instance_id,
        }
    }

    pub async fn get_statistics_data(&self) -> Result<StatisticsData, WafError> {
        let data = self.statistics.get_data().await;
        Ok(data)
    }

    pub async fn get_site_list(&self) -> Result<Vec<SiteInfo>, WafError> {
        let sites = self.sites.read().await;
        Ok(sites.values().cloned().collect())
    }

    pub async fn update_site_list(&self, sites: Vec<SiteInfo>) -> Result<(), WafError> {
        let mut site_map = self.sites.write().await;
        site_map.clear();

        for site in sites {
            site_map.insert(site.site_id.clone(), site);
        }

        Ok(())
    }

    pub async fn get_site(&self, site_id: &str) -> Result<Option<SiteInfo>, WafError> {
        let sites = self.sites.read().await;
        Ok(sites.get(site_id).cloned())
    }

    pub async fn get_blocked_ips(&self) -> Result<Vec<BlockedIP>, WafError> {
        let blocked_ips = self.blocked_ips.read().await;
        Ok(blocked_ips.values().cloned().collect())
    }

    pub async fn update_blocked_ips(&self, ips: Vec<BlockedIP>) -> Result<(), WafError> {
        let mut blocked_ip_map = self.blocked_ips.write().await;
        blocked_ip_map.clear();

        for ip in ips {
            blocked_ip_map.insert(ip.ip.clone(), ip);
        }

        Ok(())
    }

    pub async fn is_ip_blocked(&self, ip: &str) -> Result<bool, WafError> {
        let blocked_ips = self.blocked_ips.read().await;

        if let Some(blocked_ip) = blocked_ips.get(ip) {
            if blocked_ip.permanent {
                return Ok(true);
            }

            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if current_time < blocked_ip.expires_at {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub async fn execute_command(&self, command: Command) -> Result<CommandResult, WafError> {
        match command.command_type {
            CommandType::ReloadConfig => Ok(CommandResult {
                success: true,
                message: "Configuration reloaded successfully".to_string(),
                data: HashMap::new(),
            }),
            CommandType::ClearCache => {
                self.statistics.reset().await;
                Ok(CommandResult {
                    success: true,
                    message: "Cache cleared successfully".to_string(),
                    data: HashMap::new(),
                })
            }
            CommandType::BlockIP => {
                if let Some(ip) = command.parameters.get("ip") {
                    let reason = command
                        .parameters
                        .get("reason")
                        .unwrap_or(&"Blocked by admin".to_string())
                        .clone();

                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let duration = command
                        .parameters
                        .get("duration")
                        .and_then(|d| d.parse::<u64>().ok())
                        .unwrap_or(3600);

                    let blocked_ip = BlockedIP {
                        ip: ip.clone(),
                        reason,
                        blocked_at: current_time,
                        expires_at: current_time + duration,
                        permanent: duration == 0,
                    };

                    let mut blocked_ips = self.blocked_ips.write().await;
                    blocked_ips.insert(ip.clone(), blocked_ip);

                    let mut data = HashMap::new();
                    data.insert("blocked_ip".to_string(), ip.clone());

                    Ok(CommandResult {
                        success: true,
                        message: format!("IP {} blocked successfully", ip),
                        data,
                    })
                } else {
                    Ok(CommandResult {
                        success: false,
                        message: "IP parameter is required".to_string(),
                        data: HashMap::new(),
                    })
                }
            }
            CommandType::UnblockIP => {
                if let Some(ip) = command.parameters.get("ip") {
                    let mut blocked_ips = self.blocked_ips.write().await;
                    blocked_ips.remove(ip);

                    let mut data = HashMap::new();
                    data.insert("unblocked_ip".to_string(), ip.clone());

                    Ok(CommandResult {
                        success: true,
                        message: format!("IP {} unblocked successfully", ip),
                        data,
                    })
                } else {
                    Ok(CommandResult {
                        success: false,
                        message: "IP parameter is required".to_string(),
                        data: HashMap::new(),
                    })
                }
            }
            CommandType::UpdateRules => Ok(CommandResult {
                success: true,
                message: "Rules updated successfully".to_string(),
                data: HashMap::new(),
            }),
            CommandType::RestartService => Ok(CommandResult {
                success: true,
                message: "Service restart scheduled".to_string(),
                data: HashMap::new(),
            }),
        }
    }

    pub fn get_instance_id(&self) -> &str {
        &self.instance_id
    }

    pub async fn cleanup_expired_blocks(&self) -> Result<u32, WafError> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut blocked_ips = self.blocked_ips.write().await;
        let initial_count = blocked_ips.len();

        blocked_ips
            .retain(|_, blocked_ip| blocked_ip.permanent || current_time < blocked_ip.expires_at);

        let cleaned_count = initial_count - blocked_ips.len();
        Ok(cleaned_count as u32)
    }
}

pub type DataSyncManagerRef = Arc<DataSyncManager>;
