use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, Method, Uri},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::core::statistics::Statistics;
use crate::core::sync::DataSyncManager;
use crate::rules::detector::AttackDetector;
use crate::rules::model::{AttackInfo, AttackType, DetectionLevel};

/// 恶意请求分析器
#[derive(Debug, Clone)]
pub struct MaliciousRequestAnalyzer {
    sync_manager: Arc<DataSyncManager>,
    statistics: Arc<Statistics>,
    detector: Arc<AttackDetector>,
    ip_whitelist: Arc<tokio::sync::RwLock<HashSet<IpAddr>>>,
    ip_blacklist: Arc<tokio::sync::RwLock<HashMap<IpAddr, BlacklistEntry>>>,
}

/// 黑名单条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub blocked_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub block_count: u32,
}

/// 请求分析结果
#[derive(Debug, Clone)]
pub struct RequestAnalysisResult {
    pub is_malicious: bool,
    pub should_block: bool,
    pub attack_info: Option<AttackInfo>,
    pub block_reason: Option<String>,
    pub confidence_score: f64,
}

impl MaliciousRequestAnalyzer {
    /// 创建新的恶意请求分析器
    pub fn new(
        sync_manager: Arc<DataSyncManager>,
        statistics: Arc<Statistics>,
        detector: Arc<AttackDetector>,
    ) -> Self {
        Self {
            sync_manager,
            statistics,
            detector,
            ip_whitelist: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
            ip_blacklist: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// 分析请求是否恶意
    pub async fn analyze_request(
        &self,
        request: &Request<Body>,
        client_ip: IpAddr,
    ) -> RequestAnalysisResult {
        debug!(
            "分析请求: {} {} from {}",
            request.method(),
            request.uri(),
            client_ip
        );

        // 1. 检查IP白名单
        if self.is_ip_whitelisted(client_ip).await {
            debug!("IP {} 在白名单中，跳过检查", client_ip);
            return RequestAnalysisResult {
                is_malicious: false,
                should_block: false,
                attack_info: None,
                block_reason: None,
                confidence_score: 0.0,
            };
        }

        // 2. 检查IP黑名单
        if let Some(blacklist_entry) = self.is_ip_blacklisted(client_ip).await {
            warn!("IP {} 在黑名单中: {}", client_ip, blacklist_entry.reason);
            return RequestAnalysisResult {
                is_malicious: true,
                should_block: true,
                attack_info: None,
                block_reason: Some(format!("IP在黑名单中: {}", blacklist_entry.reason)),
                confidence_score: 1.0,
            };
        }

        // 3. 执行攻击检测
        let attack_result = self.detect_attacks(request).await;

        let should_block = match &attack_result {
            Some(attack_info) => {
                // 根据攻击严重程度决定是否阻止
                match attack_info.severity {
                    DetectionLevel::High => true,
                    DetectionLevel::Medium => attack_info.confidence > 0.8,
                    DetectionLevel::Low => false,
                }
            }
            None => false,
        };

        // 4. 如果检测到高危攻击，考虑将IP加入黑名单
        if let Some(ref attack_info) = attack_result {
            if attack_info.severity == DetectionLevel::High && attack_info.confidence > 0.9 {
                self.consider_blacklisting_ip(client_ip, attack_info).await;
            }
        }

        // 5. 记录统计信息
        if attack_result.is_some() {
            self.statistics.increment_defense_hit();
        } else {
            self.statistics.increment_defense_miss();
        }

        RequestAnalysisResult {
            is_malicious: attack_result.is_some(),
            should_block,
            attack_info: attack_result.clone(),
            block_reason: if should_block {
                Some("检测到恶意请求".to_string())
            } else {
                None
            },
            confidence_score: attack_result.as_ref().map(|a| a.confidence).unwrap_or(0.0),
        }
    }

    /// 检查IP是否在白名单中
    async fn is_ip_whitelisted(&self, ip: IpAddr) -> bool {
        let whitelist = self.ip_whitelist.read().await;
        whitelist.contains(&ip)
    }

    /// 检查IP是否在黑名单中
    async fn is_ip_blacklisted(&self, ip: IpAddr) -> Option<BlacklistEntry> {
        let mut blacklist = self.ip_blacklist.write().await;

        if let Some(entry) = blacklist.get(&ip) {
            // 检查是否过期
            if let Some(expires_at) = entry.expires_at {
                if SystemTime::now() > expires_at {
                    // 已过期，从黑名单中移除
                    blacklist.remove(&ip);
                    return None;
                }
            }
            Some(entry.clone())
        } else {
            None
        }
    }

    /// 执行攻击检测
    async fn detect_attacks(&self, request: &Request<Body>) -> Option<AttackInfo> {
        // 提取请求信息用于检测
        let method = request.method();
        let uri = request.uri();
        let headers = request.headers();

        // 分析URI参数
        if let Some(attack) = self.analyze_uri_attacks(uri).await {
            return Some(attack);
        }

        // 分析请求头
        if let Some(attack) = self.analyze_header_attacks(headers).await {
            return Some(attack);
        }

        // 对于POST/PUT请求，还需要分析请求体，但这里先简化处理
        if matches!(method, &Method::POST | &Method::PUT | &Method::PATCH) {
            // 注意：在实际实现中，需要读取请求体进行分析
            // 但由于Request<Body>的设计，这里需要特殊处理
            debug!("POST/PUT/PATCH请求需要进一步分析请求体");
        }

        None
    }

    /// 分析URI中的攻击模式
    async fn analyze_uri_attacks(&self, uri: &Uri) -> Option<AttackInfo> {
        let path = uri.path();
        let query = uri.query().unwrap_or("");
        let full_uri = if query.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query)
        };

        // 使用攻击检测器分析URI
        let results = self.detector.detect_all(&full_uri);
        if !results.is_empty() {
            let result = &results[0]; // 使用第一个检测结果
            Some(AttackInfo {
                attack_type: match result.attack_type.as_deref() {
                    Some("XSS") => AttackType::XSS,
                    Some("SQL Injection") => AttackType::SQLInjection,
                    Some("SSRF") => AttackType::SSRF,
                    Some("WebShell") => AttackType::WebShell,
                    _ => AttackType::Custom,
                },
                description: result
                    .description
                    .clone()
                    .unwrap_or_else(|| "检测到攻击模式".to_string()),
                confidence: 0.8, // 默认置信度
                severity: DetectionLevel::Medium,
                matched_rule: None,
                details: std::collections::HashMap::new(),
            })
        } else {
            None
        }
    }

    /// 分析请求头中的攻击模式
    async fn analyze_header_attacks(&self, headers: &HeaderMap) -> Option<AttackInfo> {
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                let header_content = format!("{}: {}", name.as_str(), value_str);

                let results = self.detector.detect_all(&header_content);
                if !results.is_empty() {
                    let result = &results[0];
                    return Some(AttackInfo {
                        attack_type: match result.attack_type.as_deref() {
                            Some("XSS") => AttackType::XSS,
                            Some("SQL Injection") => AttackType::SQLInjection,
                            Some("SSRF") => AttackType::SSRF,
                            Some("WebShell") => AttackType::WebShell,
                            _ => AttackType::Custom,
                        },
                        description: result
                            .description
                            .clone()
                            .unwrap_or_else(|| "检测到攻击模式".to_string()),
                        confidence: 0.8,
                        severity: DetectionLevel::Medium,
                        matched_rule: None,
                        details: std::collections::HashMap::new(),
                    });
                }
            }
        }
        None
    }

    /// 考虑将IP加入黑名单
    async fn consider_blacklisting_ip(&self, ip: IpAddr, attack_info: &AttackInfo) {
        let reason = format!(
            "检测到{}攻击，置信度: {:.2}",
            self.attack_type_to_string(&attack_info.attack_type),
            attack_info.confidence
        );

        // 临时拉黑1小时
        let expires_at = Some(SystemTime::now() + Duration::from_secs(3600));

        let blacklist_entry = BlacklistEntry {
            ip,
            reason: reason.clone(),
            blocked_at: SystemTime::now(),
            expires_at,
            block_count: 1,
        };

        // 添加到本地黑名单
        {
            let mut blacklist = self.ip_blacklist.write().await;
            if let Some(existing) = blacklist.get_mut(&ip) {
                existing.block_count += 1;
                existing.expires_at = expires_at;
                existing.reason = reason.clone();
            } else {
                blacklist.insert(ip, blacklist_entry);
            }
        }

        info!("IP {} 已加入黑名单: {}", ip, reason);

        // 同步到管理端
        if let Err(e) = self.sync_blacklist_to_management().await {
            error!("同步黑名单到管理端失败: {}", e);
        }

        // 记录统计信息
        self.statistics.increment_ip_block(&ip.to_string());
    }

    /// 攻击类型转字符串
    fn attack_type_to_string(&self, attack_type: &AttackType) -> &'static str {
        match attack_type {
            AttackType::XSS => "XSS",
            AttackType::SQLInjection => "SQL注入",
            AttackType::SSRF => "SSRF",
            AttackType::WebShell => "WebShell",
            AttackType::Custom => "自定义",
        }
    }

    /// 同步黑名单到管理端
    async fn sync_blacklist_to_management(&self) -> Result<(), crate::core::error::WafError> {
        let blacklist = self.ip_blacklist.read().await;
        let blocked_ips: Vec<crate::core::sync::BlockedIP> = blacklist
            .values()
            .map(|entry| crate::core::sync::BlockedIP {
                ip: entry.ip.to_string(),
                reason: entry.reason.clone(),
                blocked_at: entry
                    .blocked_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                expires_at: entry
                    .expires_at
                    .map(|t| {
                        t.duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    })
                    .unwrap_or(0),
                permanent: entry.expires_at.is_none(),
            })
            .collect();

        self.sync_manager.update_blocked_ips(blocked_ips).await
    }

    /// 添加IP到白名单
    pub async fn add_to_whitelist(&self, ip: IpAddr) {
        let mut whitelist = self.ip_whitelist.write().await;
        whitelist.insert(ip);
        info!("IP {} 已添加到白名单", ip);
    }

    /// 从白名单移除IP
    pub async fn remove_from_whitelist(&self, ip: IpAddr) -> bool {
        let mut whitelist = self.ip_whitelist.write().await;
        let removed = whitelist.remove(&ip);
        if removed {
            info!("IP {} 已从白名单移除", ip);
        }
        removed
    }

    /// 添加IP到黑名单
    pub async fn add_to_blacklist(&self, ip: IpAddr, reason: String, duration: Option<Duration>) {
        let expires_at = duration.map(|d| SystemTime::now() + d);

        let blacklist_entry = BlacklistEntry {
            ip,
            reason: reason.clone(),
            blocked_at: SystemTime::now(),
            expires_at,
            block_count: 1,
        };

        {
            let mut blacklist = self.ip_blacklist.write().await;
            blacklist.insert(ip, blacklist_entry);
        }

        info!("IP {} 已手动添加到黑名单: {}", ip, reason);

        // 同步到管理端
        if let Err(e) = self.sync_blacklist_to_management().await {
            error!("同步黑名单到管理端失败: {}", e);
        }

        self.statistics.increment_ip_block(&ip.to_string());
    }

    /// 从黑名单移除IP
    pub async fn remove_from_blacklist(&self, ip: IpAddr) -> bool {
        let mut blacklist = self.ip_blacklist.write().await;
        let removed = blacklist.remove(&ip).is_some();
        if removed {
            info!("IP {} 已从黑名单移除", ip);
        }
        removed
    }

    /// 获取黑名单统计信息
    pub async fn get_blacklist_stats(&self) -> HashMap<String, u64> {
        let blacklist = self.ip_blacklist.read().await;
        let total_blocked = blacklist.len() as u64;
        let temporary_blocks = blacklist
            .values()
            .filter(|e| e.expires_at.is_some())
            .count() as u64;
        let permanent_blocks = total_blocked - temporary_blocks;

        let mut stats = HashMap::new();
        stats.insert("total_blocked".to_string(), total_blocked);
        stats.insert("temporary_blocks".to_string(), temporary_blocks);
        stats.insert("permanent_blocks".to_string(), permanent_blocks);
        stats
    }

    /// 清理过期的黑名单条目
    pub async fn cleanup_expired_blacklist(&self) -> u32 {
        let mut blacklist = self.ip_blacklist.write().await;
        let now = SystemTime::now();
        let initial_count = blacklist.len();

        blacklist.retain(|_, entry| {
            if let Some(expires_at) = entry.expires_at {
                now <= expires_at
            } else {
                true // 永久封禁保留
            }
        });

        let removed_count = initial_count - blacklist.len();
        if removed_count > 0 {
            info!("清理了 {} 个过期的黑名单条目", removed_count);
        }

        removed_count as u32
    }

    /// 获取白名单列表
    pub async fn get_whitelist(&self) -> Vec<IpAddr> {
        let whitelist = self.ip_whitelist.read().await;
        whitelist.iter().copied().collect()
    }

    /// 获取黑名单列表
    pub async fn get_blacklist(&self) -> Vec<BlacklistEntry> {
        let blacklist = self.ip_blacklist.read().await;
        blacklist.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ip_whitelist_management() {
        let sync_manager = Arc::new(DataSyncManager::new(
            Arc::new(crate::core::statistics::Statistics::new()),
            "test".to_string(),
        ));
        let statistics = Arc::new(crate::core::statistics::Statistics::new());
        let rule_engine = crate::rules::engine::RuleEngine::new();
        let detector = Arc::new(
            AttackDetector::new(rule_engine, crate::rules::detector::DetectionLevel::Medium)
                .unwrap(),
        );

        let analyzer = MaliciousRequestAnalyzer::new(sync_manager, statistics, detector);

        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // 测试添加到白名单
        analyzer.add_to_whitelist(test_ip).await;
        assert!(analyzer.is_ip_whitelisted(test_ip).await);

        // 测试从白名单移除
        assert!(analyzer.remove_from_whitelist(test_ip).await);
        assert!(!analyzer.is_ip_whitelisted(test_ip).await);
    }

    #[tokio::test]
    async fn test_ip_blacklist_management() {
        let sync_manager = Arc::new(DataSyncManager::new(
            Arc::new(crate::core::statistics::Statistics::new()),
            "test".to_string(),
        ));
        let statistics = Arc::new(crate::core::statistics::Statistics::new());
        let rule_engine = crate::rules::engine::RuleEngine::new();
        let detector = Arc::new(
            AttackDetector::new(rule_engine, crate::rules::detector::DetectionLevel::Medium)
                .unwrap(),
        );

        let analyzer = MaliciousRequestAnalyzer::new(sync_manager, statistics, detector);

        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

        // 测试添加到黑名单
        analyzer
            .add_to_blacklist(
                test_ip,
                "测试封禁".to_string(),
                Some(Duration::from_secs(60)),
            )
            .await;

        assert!(analyzer.is_ip_blacklisted(test_ip).await.is_some());

        // 测试从黑名单移除
        assert!(analyzer.remove_from_blacklist(test_ip).await);
        assert!(analyzer.is_ip_blacklisted(test_ip).await.is_none());
    }

    #[tokio::test]
    async fn test_request_analysis() {
        let sync_manager = Arc::new(DataSyncManager::new(
            Arc::new(crate::core::statistics::Statistics::new()),
            "test".to_string(),
        ));
        let statistics = Arc::new(crate::core::statistics::Statistics::new());
        let rule_engine = crate::rules::engine::RuleEngine::new();
        let detector = Arc::new(
            AttackDetector::new(rule_engine, crate::rules::detector::DetectionLevel::Medium)
                .unwrap(),
        );

        let analyzer = MaliciousRequestAnalyzer::new(sync_manager, statistics, detector);

        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

        // 测试正常请求
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let result = analyzer.analyze_request(&request, test_ip).await;
        assert!(!result.should_block);
    }
}
