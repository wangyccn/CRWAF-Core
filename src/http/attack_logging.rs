use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{body::Body, extract::Request, http::HeaderMap};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::core::logger::FileLogger;
use crate::http::attack_analysis::RequestAnalysisResult;
use crate::rules::model::{AttackType, DetectionLevel};

/// 攻击日志记录器
#[derive(Debug, Clone)]
pub struct AttackLogger {
    logger: Arc<FileLogger>,
    attack_logs: Arc<RwLock<Vec<AttackLogEntry>>>,
    max_logs_in_memory: usize,
}

/// 攻击日志条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackLogEntry {
    pub id: String,
    pub timestamp: u64,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub attack_type: Option<String>,
    pub attack_description: Option<String>,
    pub confidence_score: f64,
    pub severity: String,
    pub blocked: bool,
    pub block_reason: Option<String>,
    pub matched_rule: Option<String>,
    pub request_headers: Vec<HeaderEntry>,
    pub request_body_sample: Option<String>,
}

/// 请求头条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

/// 攻击统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStatistics {
    pub total_attacks: u64,
    pub blocked_attacks: u64,
    pub allowed_attacks: u64,
    pub attacks_by_type: std::collections::HashMap<String, u64>,
    pub attacks_by_severity: std::collections::HashMap<String, u64>,
    pub top_attacking_ips: Vec<(String, u64)>,
    pub attacks_last_24h: u64,
}

impl AttackLogger {
    /// 创建新的攻击日志记录器
    pub fn new(logger: Arc<FileLogger>) -> Self {
        Self {
            logger,
            attack_logs: Arc::new(RwLock::new(Vec::new())),
            max_logs_in_memory: 10000, // 在内存中保持最多10000条日志
        }
    }

    /// 记录攻击日志
    pub async fn log_attack(
        &self,
        request: &Request<Body>,
        client_ip: IpAddr,
        analysis_result: &RequestAnalysisResult,
        request_body_sample: Option<String>,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let log_id = format!(
            "attack_{}_{}",
            timestamp,
            uuid::Uuid::new_v4()
                .to_string()
                .chars()
                .take(8)
                .collect::<String>()
        );

        // 提取请求信息
        let method = request.method().to_string();
        let uri = request.uri().to_string();
        let headers = request.headers();

        let host = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // 构建请求头列表
        let request_headers = self.extract_headers(headers);

        // 创建攻击日志条目
        let log_entry = if let Some(ref attack_info) = analysis_result.attack_info {
            AttackLogEntry {
                id: log_id.clone(),
                timestamp,
                client_ip: client_ip.to_string(),
                method: method.clone(),
                uri: uri.clone(),
                host,
                user_agent,
                attack_type: Some(self.attack_type_to_string(&attack_info.attack_type)),
                attack_description: Some(attack_info.description.clone()),
                confidence_score: attack_info.confidence,
                severity: self.detection_level_to_string(&attack_info.severity),
                blocked: analysis_result.should_block,
                block_reason: analysis_result.block_reason.clone(),
                matched_rule: attack_info.matched_rule.clone(),
                request_headers,
                request_body_sample,
            }
        } else {
            // 非攻击请求，但被阻止（如IP黑名单）
            AttackLogEntry {
                id: log_id.clone(),
                timestamp,
                client_ip: client_ip.to_string(),
                method: method.clone(),
                uri: uri.clone(),
                host,
                user_agent,
                attack_type: None,
                attack_description: analysis_result.block_reason.clone(),
                confidence_score: analysis_result.confidence_score,
                severity: "High".to_string(),
                blocked: analysis_result.should_block,
                block_reason: analysis_result.block_reason.clone(),
                matched_rule: None,
                request_headers,
                request_body_sample,
            }
        };

        // 记录到文件
        self.write_attack_log(&log_entry).await;

        // 保存到内存（用于快速查询）
        self.store_in_memory(log_entry).await;

        info!(
            "记录攻击日志: {} {} {} -> blocked: {}",
            client_ip, &method, &uri, analysis_result.should_block
        );
    }

    /// 提取请求头
    fn extract_headers(&self, headers: &HeaderMap) -> Vec<HeaderEntry> {
        headers
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|v| HeaderEntry {
                    name: name.to_string(),
                    value: v.to_string(),
                })
            })
            .collect()
    }

    /// 攻击类型转字符串
    fn attack_type_to_string(&self, attack_type: &AttackType) -> String {
        match attack_type {
            AttackType::XSS => "XSS".to_string(),
            AttackType::SQLInjection => "SQL_INJECTION".to_string(),
            AttackType::SSRF => "SSRF".to_string(),
            AttackType::WebShell => "WEB_SHELL".to_string(),
            AttackType::Custom => "CUSTOM".to_string(),
        }
    }

    /// 检测级别转字符串
    fn detection_level_to_string(&self, level: &DetectionLevel) -> String {
        match level {
            DetectionLevel::Low => "Low".to_string(),
            DetectionLevel::Medium => "Medium".to_string(),
            DetectionLevel::High => "High".to_string(),
        }
    }

    /// 写入攻击日志到文件
    async fn write_attack_log(&self, log_entry: &AttackLogEntry) {
        if let Ok(log_json) = serde_json::to_string(log_entry) {
            let _ = self.logger.attack(&log_json);
        } else {
            error!("序列化攻击日志失败");
        }
    }

    /// 将日志保存到内存
    async fn store_in_memory(&self, log_entry: AttackLogEntry) {
        let mut logs = self.attack_logs.write().await;

        // 如果超过最大容量，移除最老的日志
        if logs.len() >= self.max_logs_in_memory {
            logs.remove(0);
        }

        logs.push(log_entry);
    }

    /// 获取最近的攻击日志
    pub async fn get_recent_attacks(&self, limit: usize) -> Vec<AttackLogEntry> {
        let logs = self.attack_logs.read().await;
        let start = if logs.len() > limit {
            logs.len() - limit
        } else {
            0
        };
        logs[start..].to_vec()
    }

    /// 根据条件查询攻击日志
    pub async fn query_attacks(&self, filter: &AttackLogFilter) -> Vec<AttackLogEntry> {
        let logs = self.attack_logs.read().await;

        logs.iter()
            .filter(|log| self.matches_filter(log, filter))
            .cloned()
            .collect()
    }

    /// 检查日志条目是否匹配过滤条件
    fn matches_filter(&self, log: &AttackLogEntry, filter: &AttackLogFilter) -> bool {
        // 时间范围过滤
        if let Some(start_time) = filter.start_time {
            if log.timestamp < start_time {
                return false;
            }
        }

        if let Some(end_time) = filter.end_time {
            if log.timestamp > end_time {
                return false;
            }
        }

        // IP过滤
        if let Some(ref ip) = filter.client_ip {
            if !log.client_ip.contains(ip) {
                return false;
            }
        }

        // 攻击类型过滤
        if let Some(ref attack_type) = filter.attack_type {
            if log.attack_type.as_ref() != Some(attack_type) {
                return false;
            }
        }

        // 严重性过滤
        if let Some(ref severity) = filter.severity {
            if &log.severity != severity {
                return false;
            }
        }

        // 阻止状态过滤
        if let Some(blocked) = filter.blocked {
            if log.blocked != blocked {
                return false;
            }
        }

        true
    }

    /// 获取攻击统计信息
    pub async fn get_attack_statistics(&self) -> AttackStatistics {
        let logs = self.attack_logs.read().await;

        let total_attacks = logs.len() as u64;
        let blocked_attacks = logs.iter().filter(|l| l.blocked).count() as u64;
        let allowed_attacks = total_attacks - blocked_attacks;

        // 按攻击类型统计
        let mut attacks_by_type = std::collections::HashMap::new();
        for log in logs.iter() {
            if let Some(ref attack_type) = log.attack_type {
                *attacks_by_type.entry(attack_type.clone()).or_insert(0) += 1;
            }
        }

        // 按严重性统计
        let mut attacks_by_severity = std::collections::HashMap::new();
        for log in logs.iter() {
            *attacks_by_severity.entry(log.severity.clone()).or_insert(0) += 1;
        }

        // 统计攻击最多的IP
        let mut ip_counts = std::collections::HashMap::new();
        for log in logs.iter() {
            *ip_counts.entry(log.client_ip.clone()).or_insert(0) += 1;
        }

        let mut top_attacking_ips: Vec<(String, u64)> = ip_counts.into_iter().collect();
        top_attacking_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_attacking_ips.truncate(10); // 保留前10个

        // 最近24小时的攻击
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let day_ago = now - 86400; // 24 * 60 * 60

        let attacks_last_24h = logs.iter().filter(|l| l.timestamp >= day_ago).count() as u64;

        AttackStatistics {
            total_attacks,
            blocked_attacks,
            allowed_attacks,
            attacks_by_type,
            attacks_by_severity,
            top_attacking_ips,
            attacks_last_24h,
        }
    }

    /// 清理旧的攻击日志
    pub async fn cleanup_old_logs(&self, hours_to_keep: u64) -> u32 {
        let mut logs = self.attack_logs.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff_time = now - (hours_to_keep * 3600);

        let initial_count = logs.len();
        logs.retain(|log| log.timestamp >= cutoff_time);
        let removed_count = initial_count - logs.len();

        if removed_count > 0 {
            info!("清理了 {} 条旧的攻击日志", removed_count);
        }

        removed_count as u32
    }

    /// 导出攻击日志
    pub async fn export_logs(&self, format: &str) -> Result<String, Box<dyn std::error::Error>> {
        let logs = self.attack_logs.read().await;

        match format.to_lowercase().as_str() {
            "json" => Ok(serde_json::to_string_pretty(&*logs)?),
            "csv" => {
                let mut csv_data = String::new();
                csv_data.push_str(
                    "ID,Timestamp,Client IP,Method,URI,Attack Type,Severity,Blocked,Description\n",
                );

                for log in logs.iter() {
                    csv_data.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        log.id,
                        log.timestamp,
                        log.client_ip,
                        log.method,
                        log.uri,
                        log.attack_type.as_deref().unwrap_or("N/A"),
                        log.severity,
                        log.blocked,
                        log.attack_description.as_deref().unwrap_or("N/A")
                    ));
                }

                Ok(csv_data)
            }
            _ => Err("不支持的导出格式".into()),
        }
    }
}

/// 攻击日志过滤器
#[derive(Debug, Clone, Default)]
pub struct AttackLogFilter {
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub client_ip: Option<String>,
    pub attack_type: Option<String>,
    pub severity: Option<String>,
    pub blocked: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_attack_logger_creation() {
        let log_config = crate::core::logger::LogConfig {
            log_dir: "test_logs".to_string(),
            prefix: "test".to_string(),
            rotation_policy: crate::core::logger::RotationPolicy::Never,
            compression_policy: crate::core::logger::CompressionPolicy::None,
            max_files: Some(5),
        };
        let logger = Arc::new(crate::core::logger::FileLogger::new(log_config).unwrap());
        let attack_logger = AttackLogger::new(logger);

        let stats = attack_logger.get_attack_statistics().await;
        assert_eq!(stats.total_attacks, 0);
    }

    #[tokio::test]
    async fn test_attack_log_storage() {
        let log_config = crate::core::logger::LogConfig {
            log_dir: "test_logs".to_string(),
            prefix: "test".to_string(),
            rotation_policy: crate::core::logger::RotationPolicy::Never,
            compression_policy: crate::core::logger::CompressionPolicy::None,
            max_files: Some(5),
        };
        let logger = Arc::new(crate::core::logger::FileLogger::new(log_config).unwrap());
        let attack_logger = AttackLogger::new(logger);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test?param=%3Cscript%3Ealert(1)%3C/script%3E")
            .header("host", "example.com")
            .header("user-agent", "TestAgent/1.0")
            .body(Body::empty())
            .unwrap();

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        let analysis_result = RequestAnalysisResult {
            is_malicious: true,
            should_block: true,
            attack_info: Some(crate::rules::model::AttackInfo {
                attack_type: AttackType::XSS,
                description: "检测到XSS攻击".to_string(),
                confidence: 0.95,
                severity: DetectionLevel::High,
                matched_rule: Some("XSS_RULE_01".to_string()),
                details: std::collections::HashMap::new(),
            }),
            block_reason: Some("检测到恶意脚本".to_string()),
            confidence_score: 0.95,
        };

        attack_logger
            .log_attack(&request, client_ip, &analysis_result, None)
            .await;

        let recent_attacks = attack_logger.get_recent_attacks(10).await;
        assert_eq!(recent_attacks.len(), 1);
        assert!(recent_attacks[0].blocked);
        assert_eq!(recent_attacks[0].attack_type, Some("XSS".to_string()));
    }

    #[tokio::test]
    async fn test_attack_statistics() {
        let log_config = crate::core::logger::LogConfig {
            log_dir: "test_logs".to_string(),
            prefix: "test".to_string(),
            rotation_policy: crate::core::logger::RotationPolicy::Never,
            compression_policy: crate::core::logger::CompressionPolicy::None,
            max_files: Some(5),
        };
        let logger = Arc::new(crate::core::logger::FileLogger::new(log_config).unwrap());
        let attack_logger = AttackLogger::new(logger);

        // 模拟多个攻击日志
        for i in 0..5 {
            let request = Request::builder()
                .method(Method::GET)
                .uri(&format!("/test{}", i))
                .body(Body::empty())
                .unwrap();

            let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100 + i as u8));

            let analysis_result = RequestAnalysisResult {
                is_malicious: true,
                should_block: i % 2 == 0, // 一半被阻止
                attack_info: Some(crate::rules::model::AttackInfo {
                    attack_type: if i % 2 == 0 {
                        AttackType::XSS
                    } else {
                        AttackType::SQLInjection
                    },
                    description: "测试攻击".to_string(),
                    confidence: 0.8,
                    severity: DetectionLevel::Medium,
                    matched_rule: Some(format!("RULE_{}", i)),
                    details: std::collections::HashMap::new(),
                }),
                block_reason: if i % 2 == 0 {
                    Some("阻止".to_string())
                } else {
                    None
                },
                confidence_score: 0.8,
            };

            attack_logger
                .log_attack(&request, client_ip, &analysis_result, None)
                .await;
        }

        let stats = attack_logger.get_attack_statistics().await;
        assert_eq!(stats.total_attacks, 5);
        assert_eq!(stats.blocked_attacks, 3); // 0, 2, 4被阻止
        assert_eq!(stats.allowed_attacks, 2);
    }
}
