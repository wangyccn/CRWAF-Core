use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

/// 会话信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub user_ip: String,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub browser_fingerprint: String,
    pub created_at: SystemTime,
    pub last_access: SystemTime,
    pub access_count: u64,
    pub is_validated: bool,
    pub validation_level: ValidationLevel,
}

/// 验证级别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationLevel {
    /// 未验证
    None,
    /// 基础验证（通过五秒盾）
    Basic,
    /// 高级验证（通过验证码）
    Advanced,
    /// 完全验证（通过所有检查）
    Complete,
}

/// 请求信息
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub request_id: String,
    pub session_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub url: String,
    pub method: String,
    pub timestamp: SystemTime,
    pub headers: HashMap<String, String>,
}

/// 设备指纹信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub screen_resolution: String,
    pub timezone: String,
    pub language: String,
    pub platform: String,
    pub plugins: Vec<String>,
    pub canvas_fingerprint: String,
    pub webgl_fingerprint: String,
}

/// 浏览器指纹信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub user_agent: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub accept: String,
    pub connection: String,
    pub cache_control: String,
}

/// 身份识别服务
#[allow(dead_code)]
pub struct IdentityService {
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    requests: Arc<RwLock<HashMap<String, RequestInfo>>>,
    session_ttl: Duration,
    request_ttl: Duration,
}

#[allow(dead_code)]
impl IdentityService {
    /// 创建新的身份识别服务
    /// `session_ttl_secs` 和 `request_ttl_secs` 以秒为单位
    pub fn new(session_ttl_secs: u64, request_ttl_secs: u64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            requests: Arc::new(RwLock::new(HashMap::new())),
            session_ttl: Duration::from_secs(session_ttl_secs),
            request_ttl: Duration::from_secs(request_ttl_secs),
        }
    }

    /// 生成会话ID
    pub fn generate_session_id() -> String {
        let uuid = Uuid::new_v4();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        format!("WAF_{}_{}", timestamp, uuid.simple())
    }

    /// 生成请求ID
    pub fn generate_request_id() -> String {
        let uuid = Uuid::new_v4();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        format!("REQ_{}_{}", timestamp, uuid.simple())
    }

    /// 生成设备指纹
    pub fn generate_device_fingerprint(device_info: &DeviceFingerprint) -> String {
        let mut hasher = Sha256::new();

        hasher.update(device_info.screen_resolution.as_bytes());
        hasher.update(device_info.timezone.as_bytes());
        hasher.update(device_info.language.as_bytes());
        hasher.update(device_info.platform.as_bytes());
        hasher.update(device_info.canvas_fingerprint.as_bytes());
        hasher.update(device_info.webgl_fingerprint.as_bytes());

        for plugin in &device_info.plugins {
            hasher.update(plugin.as_bytes());
        }

        let result = hasher.finalize();
        general_purpose::STANDARD.encode(result)[..16].to_string()
    }

    /// 生成浏览器指纹
    pub fn generate_browser_fingerprint(browser_info: &BrowserFingerprint) -> String {
        let mut hasher = Sha256::new();

        hasher.update(browser_info.user_agent.as_bytes());
        hasher.update(browser_info.accept_language.as_bytes());
        hasher.update(browser_info.accept_encoding.as_bytes());
        hasher.update(browser_info.accept.as_bytes());
        hasher.update(browser_info.connection.as_bytes());
        hasher.update(browser_info.cache_control.as_bytes());

        let result = hasher.finalize();
        general_purpose::STANDARD.encode(result)[..16].to_string()
    }

    /// 从HTTP头部提取浏览器指纹
    pub fn extract_browser_fingerprint_from_headers(
        headers: &HashMap<String, String>,
    ) -> BrowserFingerprint {
        BrowserFingerprint {
            user_agent: headers.get("user-agent").unwrap_or(&String::new()).clone(),
            accept_language: headers
                .get("accept-language")
                .unwrap_or(&String::new())
                .clone(),
            accept_encoding: headers
                .get("accept-encoding")
                .unwrap_or(&String::new())
                .clone(),
            accept: headers.get("accept").unwrap_or(&String::new()).clone(),
            connection: headers.get("connection").unwrap_or(&String::new()).clone(),
            cache_control: headers
                .get("cache-control")
                .unwrap_or(&String::new())
                .clone(),
        }
    }

    /// 创建或更新会话
    pub async fn create_or_update_session(
        &self,
        ip_address: &str,
        user_agent: &str,
        device_fingerprint: &str,
        browser_fingerprint: &str,
    ) -> String {
        let mut sessions = self.sessions.write().await;

        // 查找现有会话
        let existing_session = sessions.values().find(|session| {
            session.user_ip == ip_address
                && session.device_fingerprint == device_fingerprint
                && session.browser_fingerprint == browser_fingerprint
        });

        if let Some(existing) = existing_session {
            let session_id = existing.session_id.clone();

            // 更新现有会话
            if let Some(session) = sessions.get_mut(&session_id) {
                session.last_access = SystemTime::now();
                session.access_count += 1;
            }

            session_id
        } else {
            // 创建新会话
            let session_id = Self::generate_session_id();
            let now = SystemTime::now();

            let session_info = SessionInfo {
                session_id: session_id.clone(),
                user_ip: ip_address.to_string(),
                user_agent: user_agent.to_string(),
                device_fingerprint: device_fingerprint.to_string(),
                browser_fingerprint: browser_fingerprint.to_string(),
                created_at: now,
                last_access: now,
                access_count: 1,
                is_validated: false,
                validation_level: ValidationLevel::None,
            };

            sessions.insert(session_id.clone(), session_info);
            session_id
        }
    }

    /// 创建请求记录
    pub async fn create_request(
        &self,
        session_id: &str,
        ip_address: &str,
        user_agent: &str,
        url: &str,
        method: &str,
        headers: HashMap<String, String>,
    ) -> String {
        let request_id = Self::generate_request_id();
        let mut requests = self.requests.write().await;

        let request_info = RequestInfo {
            request_id: request_id.clone(),
            session_id: session_id.to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            url: url.to_string(),
            method: method.to_string(),
            timestamp: SystemTime::now(),
            headers,
        };

        requests.insert(request_id.clone(), request_info);
        request_id
    }

    /// 获取会话信息
    pub async fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// 获取请求信息
    pub async fn get_request(&self, request_id: &str) -> Option<RequestInfo> {
        let requests = self.requests.read().await;
        requests.get(request_id).cloned()
    }

    /// 更新会话验证状态
    pub async fn update_session_validation(
        &self,
        session_id: &str,
        is_validated: bool,
        validation_level: ValidationLevel,
    ) -> bool {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.is_validated = is_validated;
            session.validation_level = validation_level;
            session.last_access = SystemTime::now();
            true
        } else {
            false
        }
    }

    /// 检查会话是否已验证
    pub async fn is_session_validated(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().await;

        if let Some(session) = sessions.get(session_id) {
            session.is_validated && self.is_session_valid(session)
        } else {
            false
        }
    }

    /// 检查会话是否有效（未过期）
    fn is_session_valid(&self, session: &SessionInfo) -> bool {
        let now = SystemTime::now();

        match now.duration_since(session.last_access) {
            Ok(elapsed) => elapsed < self.session_ttl,
            Err(_) => false,
        }
    }

    /// 获取IP地址的活跃会话数
    pub async fn get_active_sessions_for_ip(&self, ip_address: &str) -> usize {
        let sessions = self.sessions.read().await;
        let _now = SystemTime::now();

        sessions
            .values()
            .filter(|session| session.user_ip == ip_address && self.is_session_valid(session))
            .count()
    }

    /// 获取会话的请求历史
    pub async fn get_session_requests(&self, session_id: &str) -> Vec<RequestInfo> {
        let requests = self.requests.read().await;

        let mut result: Vec<RequestInfo> = requests
            .values()
            .filter(|request| request.session_id == session_id)
            .cloned()
            .collect();
        use std::cmp::Ordering;
        use std::time::UNIX_EPOCH;

        result.sort_by(|a, b| {
            let at = a
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let bt = b
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            match at.cmp(&bt) {
                Ordering::Equal => a.request_id.cmp(&b.request_id),
                other => other,
            }
        });
        result
    }

    /// 清理过期的会话和请求
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now();

        // 清理过期会话
        {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| match now.duration_since(session.last_access) {
                Ok(elapsed) => elapsed < self.session_ttl,
                Err(_) => false,
            });
        }

        // 清理过期请求
        {
            let mut requests = self.requests.write().await;
            requests.retain(|_, request| match now.duration_since(request.timestamp) {
                Ok(elapsed) => elapsed < self.request_ttl,
                Err(_) => false,
            });
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> IdentityStats {
        let sessions = self.sessions.read().await;
        let requests = self.requests.read().await;

        let validated_sessions = sessions.values().filter(|s| s.is_validated).count();
        let unique_ips = sessions
            .values()
            .map(|s| &s.user_ip)
            .collect::<std::collections::HashSet<_>>()
            .len();

        IdentityStats {
            total_sessions: sessions.len(),
            validated_sessions,
            total_requests: requests.len(),
            unique_ips,
        }
    }

    /// 删除会话
    pub async fn remove_session(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id).is_some()
    }

    /// 删除IP的所有会话
    pub async fn remove_sessions_for_ip(&self, ip_address: &str) -> usize {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, session| session.user_ip != ip_address);

        initial_count - sessions.len()
    }
}

/// 身份识别统计信息
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityStats {
    pub total_sessions: usize,
    pub validated_sessions: usize,
    pub total_requests: usize,
    pub unique_ips: usize,
}

impl Default for IdentityService {
    fn default() -> Self {
        Self::new(24, 60) // 24小时会话，60分钟请求
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_generation() {
        let service = IdentityService::default();

        let session_id = service
            .create_or_update_session("192.168.1.1", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        assert!(session_id.starts_with("WAF_"));

        let session = service.get_session(&session_id).await.unwrap();
        assert_eq!(session.user_ip, "192.168.1.1");
        assert_eq!(session.access_count, 1);
    }

    #[tokio::test]
    async fn test_request_generation() {
        let service = IdentityService::default();
        let session_id = "test_session";

        let request_id = service
            .create_request(
                session_id,
                "192.168.1.1",
                "Mozilla/5.0",
                "/test",
                "GET",
                HashMap::new(),
            )
            .await;

        assert!(request_id.starts_with("REQ_"));

        let request = service.get_request(&request_id).await.unwrap();
        assert_eq!(request.session_id, session_id);
        assert_eq!(request.url, "/test");
    }

    #[tokio::test]
    async fn test_fingerprint_generation() {
        let device_info = DeviceFingerprint {
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC+8".to_string(),
            language: "zh-CN".to_string(),
            platform: "Windows".to_string(),
            plugins: vec!["Chrome PDF Plugin".to_string()],
            canvas_fingerprint: "canvas_hash".to_string(),
            webgl_fingerprint: "webgl_hash".to_string(),
        };

        let fp1 = IdentityService::generate_device_fingerprint(&device_info);
        let fp2 = IdentityService::generate_device_fingerprint(&device_info);

        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }

    #[tokio::test]
    async fn test_session_validation() {
        let service = IdentityService::default();

        let session_id = service
            .create_or_update_session("192.168.1.1", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        assert!(!service.is_session_validated(&session_id).await);

        service
            .update_session_validation(&session_id, true, ValidationLevel::Basic)
            .await;

        assert!(service.is_session_validated(&session_id).await);
    }
}
