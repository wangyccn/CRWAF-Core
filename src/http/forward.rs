use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::core::statistics::Statistics;
use crate::core::sync::{DataSyncManager, SiteInfo};
use crate::http::middleware::error::HttpError;

/// 请求转发配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardConfig {
    pub timeout_seconds: u64,
    pub max_redirects: usize,
    pub preserve_host_header: bool,
    pub add_waf_headers: bool,
    pub remove_headers: Vec<String>,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_redirects: 5,
            preserve_host_header: true,
            add_waf_headers: true,
            remove_headers: vec![
                "connection".to_string(),
                "transfer-encoding".to_string(),
                "content-length".to_string(),
            ],
        }
    }
}

/// 后端服务器信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    pub host: String,
    pub port: u16,
    pub protocol: String, // http 或 https
    pub weight: u32,
    pub health_check_path: String,
    pub is_healthy: bool,
}

impl BackendServer {
    #[allow(dead_code)]
    pub fn get_base_url(&self) -> String {
        format!("{}://{}:{}", self.protocol, self.host, self.port)
    }
}

/// 网站配置信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfig {
    pub domain: String,
    pub backends: Vec<BackendServer>,
    pub forward_config: ForwardConfig,
    pub is_enabled: bool,
}

/// 请求转发服务
#[allow(dead_code)]
pub struct ForwardService {
    client: Client,
    sites: Arc<tokio::sync::RwLock<HashMap<String, SiteConfig>>>,
}

/// 集成的WAF请求转发器
#[derive(Debug, Clone)]
pub struct WafRequestForwarder {
    client: Client,
    sync_manager: Arc<DataSyncManager>,
    statistics: Arc<Statistics>,
}

impl WafRequestForwarder {
    /// 创建新的WAF请求转发器
    pub fn new(sync_manager: Arc<DataSyncManager>, statistics: Arc<Statistics>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .user_agent("CRWAF/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            sync_manager,
            statistics,
        }
    }

    /// 处理HTTP请求 - 主要入口点
    pub async fn handle_request(
        &self,
        request: Request<Body>,
    ) -> Result<Response<Body>, HttpError> {
        let start_time = std::time::Instant::now();

        // 1. 获取Host头
        let host = self.extract_host(&request)?;
        debug!("处理请求到主机: {}", host);

        // 2. 检查网站有效性
        let site_info = match self.validate_site(&host).await {
            Ok(Some(site)) => site,
            Ok(None) => {
                warn!("未找到网站配置: {}", host);
                return Ok(self.create_404_response());
            }
            Err(e) => {
                error!("检查网站有效性失败: {}", e);
                return Err(HttpError::InternalServerError("网站验证失败".to_string()));
            }
        };

        if !site_info.enabled {
            warn!("网站已禁用: {}", host);
            return Ok(self.create_404_response());
        }

        info!(
            "转发请求: {} {} -> {}",
            request.method(),
            request.uri(),
            site_info.origin
        );

        // 3. 转发请求
        let response = self.forward_request(request, &site_info).await?;

        // 4. 记录统计信息
        self.statistics.increment_request();
        let duration = start_time.elapsed();
        debug!("请求处理完成，耗时: {:?}", duration);

        Ok(response)
    }

    /// 提取Host头
    fn extract_host(&self, request: &Request<Body>) -> Result<String, HttpError> {
        // 首先尝试从Host头获取
        if let Some(host_value) = request.headers().get("host") {
            if let Ok(host_str) = host_value.to_str() {
                // 移除端口号（如果存在）
                let host = host_str.split(':').next().unwrap_or(host_str);
                return Ok(host.to_string());
            }
        }

        // 如果Host头不存在，尝试从URI获取
        if let Some(host) = request.uri().host() {
            return Ok(host.to_string());
        }

        Err(HttpError::BadRequest("缺少Host头".to_string()))
    }

    /// 验证网站配置
    async fn validate_site(
        &self,
        host: &str,
    ) -> Result<Option<SiteInfo>, crate::core::error::WafError> {
        let sites = self.sync_manager.get_site_list().await?;

        // 查找匹配的网站
        for site in sites {
            if site.domain == host || self.domain_matches(&site.domain, host) {
                return Ok(Some(site));
            }
        }

        Ok(None)
    }

    /// 检查域名是否匹配（支持通配符）
    fn domain_matches(&self, pattern: &str, host: &str) -> bool {
        if pattern == host {
            return true;
        }

        // 支持简单的通配符匹配，如 *.example.com
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            return host.ends_with(suffix) && (host.len() > suffix.len());
        }

        false
    }

    /// 转发请求到后端服务器
    async fn forward_request(
        &self,
        request: Request<Body>,
        site_info: &SiteInfo,
    ) -> Result<Response<Body>, HttpError> {
        // 构建后端URL
        let backend_url = self.build_backend_url(&request, site_info)?;
        debug!("转发到后端URL: {}", backend_url);

        // 获取请求信息
        let method = request.method().clone();
        let headers = request.headers().clone();
        let body = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .map_err(|e| HttpError::BadRequest(format!("读取请求体失败: {}", e)))?;

        // 创建后端请求
        let mut backend_request = self
            .client
            .request(self.convert_method(method), &backend_url)
            .body(body.to_vec());

        // 复制原始请求头，但排除一些不应转发的头
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if !self.should_skip_header(&name_str) {
                if let (Ok(header_name), Ok(header_value)) = (
                    name.as_str().parse::<reqwest::header::HeaderName>(),
                    value.to_str(),
                ) {
                    backend_request = backend_request.header(header_name, header_value);
                }
            }
        }

        // 添加WAF标识头
        backend_request = backend_request.header("X-Forwarded-By", "CRWAF");
        backend_request = backend_request.header("X-WAF-Version", env!("CARGO_PKG_VERSION"));

        // 发送请求
        let backend_response = timeout(Duration::from_secs(30), backend_request.send())
            .await
            .map_err(|_| HttpError::InternalServerError("后端请求超时".to_string()))?
            .map_err(|e| {
                error!("后端请求失败: {}", e);
                HttpError::BadGateway(format!("后端请求失败: {}", e))
            })?;

        // 构建响应
        self.build_waf_response(backend_response).await
    }

    /// 转换HTTP方法
    fn convert_method(&self, method: axum::http::Method) -> reqwest::Method {
        match method {
            axum::http::Method::GET => reqwest::Method::GET,
            axum::http::Method::POST => reqwest::Method::POST,
            axum::http::Method::PUT => reqwest::Method::PUT,
            axum::http::Method::DELETE => reqwest::Method::DELETE,
            axum::http::Method::PATCH => reqwest::Method::PATCH,
            axum::http::Method::HEAD => reqwest::Method::HEAD,
            axum::http::Method::OPTIONS => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET, // 默认使用GET
        }
    }

    /// 构建后端URL
    fn build_backend_url(
        &self,
        request: &Request<Body>,
        site_info: &SiteInfo,
    ) -> Result<String, HttpError> {
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let backend_url = format!(
            "{}{}",
            site_info.origin.trim_end_matches('/'),
            path_and_query
        );

        Ok(backend_url)
    }

    /// 检查是否应该跳过转发某个请求头
    fn should_skip_header(&self, header_name: &str) -> bool {
        matches!(
            header_name,
            "host"
                | "connection"
                | "upgrade"
                | "proxy-connection"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
        )
    }

    /// 构建WAF响应
    async fn build_waf_response(
        &self,
        backend_response: reqwest::Response,
    ) -> Result<Response<Body>, HttpError> {
        let status = backend_response.status();
        let headers = backend_response.headers().clone();

        // 读取响应体
        let body_bytes = backend_response
            .bytes()
            .await
            .map_err(|e| HttpError::BadGateway(format!("读取后端响应失败: {}", e)))?;

        // 构建Axum响应
        let axum_status = axum::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let mut response_builder = Response::builder().status(axum_status);

        // 复制响应头，但跳过一些不应转发的头
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if !self.should_skip_response_header(&name_str) {
                if let (Ok(axum_name), Ok(axum_value)) = (
                    HeaderName::from_bytes(name.as_str().as_bytes()),
                    HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    response_builder = response_builder.header(axum_name, axum_value);
                }
            }
        }

        // 添加WAF响应头
        response_builder = response_builder.header("X-Protected-By", "CRWAF");

        let response = response_builder
            .body(Body::from(body_bytes))
            .map_err(|e| HttpError::InternalServerError(format!("构建响应失败: {}", e)))?;

        Ok(response)
    }

    /// 检查是否应该跳过转发某个响应头
    fn should_skip_response_header(&self, header_name: &str) -> bool {
        matches!(
            header_name,
            "connection" | "upgrade" | "proxy-connection" | "te" | "trailers" | "transfer-encoding"
        )
    }

    /// 创建404响应
    fn create_404_response(&self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("X-Protected-By", "CRWAF")
            .body(Body::from(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>404 - 页面未找到</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .error { color: #e74c3c; }
        .info { color: #7f8c8d; margin-top: 20px; }
    </style>
</head>
<body>
    <h1 class="error">404 - 页面未找到</h1>
    <p>请求的资源不存在或网站配置无效。</p>
    <div class="info">Protected by CRWAF</div>
</body>
</html>"#,
            ))
            .unwrap()
    }
}

#[allow(dead_code)]
impl ForwardService {
    /// 创建新的转发服务
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            sites: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// 更新网站配置
    pub async fn update_site_config(&self, domain: String, config: SiteConfig) {
        let mut sites = self.sites.write().await;
        sites.insert(domain, config);
    }

    /// 删除网站配置
    pub async fn remove_site_config(&self, domain: &str) -> bool {
        let mut sites = self.sites.write().await;
        sites.remove(domain).is_some()
    }

    /// 获取网站配置
    pub async fn get_site_config(&self, domain: &str) -> Option<SiteConfig> {
        let sites = self.sites.read().await;
        sites.get(domain).cloned()
    }

    /// 检查网站是否存在且启用
    pub async fn is_site_enabled(&self, domain: &str) -> bool {
        let sites = self.sites.read().await;

        if let Some(site) = sites.get(domain) {
            site.is_enabled && !site.backends.is_empty()
        } else {
            false
        }
    }

    /// 选择后端服务器（简单轮询）
    fn select_backend<'a>(&self, backends: &'a [BackendServer]) -> Option<&'a BackendServer> {
        // 只选择健康的服务器
        let healthy_backends: Vec<&BackendServer> =
            backends.iter().filter(|b| b.is_healthy).collect();

        if healthy_backends.is_empty() {
            return None;
        }

        // 简单轮询策略，根据权重选择
        let total_weight: u32 = healthy_backends.iter().map(|b| b.weight).sum();
        if total_weight == 0 {
            return healthy_backends.first().copied();
        }

        // 这里应该实现更复杂的负载均衡逻辑
        // 现在简单返回第一个健康的服务器
        healthy_backends.first().copied()
    }

    /// 转发请求
    pub async fn forward_request(
        &self,
        domain: &str,
        request: Request<Body>,
    ) -> Result<Response, HttpError> {
        // 获取网站配置
        let site_config = self
            .get_site_config(domain)
            .await
            .ok_or_else(|| HttpError::NotFound(format!("网站 {domain} 未配置")))?;

        if !site_config.is_enabled {
            return Err(HttpError::BadRequest(format!("网站 {domain} 已禁用")));
        }

        // 选择后端服务器
        let backend = self
            .select_backend(&site_config.backends)
            .ok_or_else(|| HttpError::ServiceUnavailable("没有可用的后端服务器".to_string()))?;

        // 构建目标URL
        let target_url = format!(
            "{}{}",
            backend.get_base_url(),
            request
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
        );

        // 转发请求
        self.proxy_request(request, &target_url, &site_config.forward_config)
            .await
    }

    /// 代理请求到目标服务器
    async fn proxy_request(
        &self,
        request: Request<Body>,
        target_url: &str,
        config: &ForwardConfig,
    ) -> Result<Response, HttpError> {
        let method = request.method().clone();
        let headers = request.headers().clone();
        let body = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .map_err(|e| HttpError::BadRequest(format!("读取请求体失败: {e}")))?;

        // 构建reqwest方法
        let reqwest_method = match method {
            axum::http::Method::GET => reqwest::Method::GET,
            axum::http::Method::POST => reqwest::Method::POST,
            axum::http::Method::PUT => reqwest::Method::PUT,
            axum::http::Method::DELETE => reqwest::Method::DELETE,
            axum::http::Method::PATCH => reqwest::Method::PATCH,
            axum::http::Method::HEAD => reqwest::Method::HEAD,
            axum::http::Method::OPTIONS => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET, // 默认使用GET
        };

        let mut req_builder = self.client.request(reqwest_method, target_url);

        // 处理请求头
        let mut reqwest_headers = reqwest::header::HeaderMap::new();
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();

            // 跳过需要移除的头部
            if config.remove_headers.contains(&name_str) {
                continue;
            }

            // 转换头部名称和值
            if let (Ok(reqwest_name), Ok(reqwest_value)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                reqwest_headers.insert(reqwest_name, reqwest_value);
            }
        }

        // 添加WAF标识头部
        if config.add_waf_headers {
            if let Ok(waf_version) =
                reqwest::header::HeaderValue::from_str(env!("CARGO_PKG_VERSION"))
            {
                reqwest_headers.insert("x-waf-version", waf_version);
            }
            if let Ok(forwarded_by) = reqwest::header::HeaderValue::from_str("CRWAF") {
                reqwest_headers.insert("x-forwarded-by", forwarded_by);
            }
        }

        req_builder = req_builder.headers(reqwest_headers);

        // 添加请求体
        if !body.is_empty() {
            req_builder = req_builder.body(body);
        }

        // 设置超时并发送请求
        let response = timeout(
            Duration::from_secs(config.timeout_seconds),
            req_builder.send(),
        )
        .await
        .map_err(|_| HttpError::Timeout("请求超时".to_string()))?
        .map_err(|e| HttpError::BadGateway(format!("转发请求失败: {e}")))?;

        // 构建响应
        self.build_response(response).await
    }

    /// 构建响应
    async fn build_response(&self, response: reqwest::Response) -> Result<Response, HttpError> {
        let status = StatusCode::from_u16(response.status().as_u16())
            .map_err(|e| HttpError::BadGateway(format!("无效的响应状态码: {e}")))?;

        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map_err(|e| HttpError::BadGateway(format!("读取响应体失败: {e}")))?;

        // 构建Axum响应
        let mut builder = Response::builder().status(status);

        // 添加响应头，跳过一些不应该转发的头部
        let skip_headers = ["connection", "transfer-encoding", "content-length"];
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if !skip_headers.contains(&name_str.as_str()) {
                // 转换reqwest header到axum header
                if let (Ok(axum_name), Ok(axum_value)) = (
                    HeaderName::from_bytes(name.as_str().as_bytes()),
                    HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    builder = builder.header(axum_name, axum_value);
                }
            }
        }

        let response = builder
            .body(Body::from(body))
            .map_err(|e| HttpError::InternalServerError(format!("构建响应失败: {e}")))?;

        Ok(response)
    }

    /// 执行健康检查
    pub async fn health_check(&self, backend: &BackendServer) -> bool {
        let health_url = format!("{}{}", backend.get_base_url(), backend.health_check_path);

        match timeout(Duration::from_secs(5), self.client.get(&health_url).send()).await {
            Ok(Ok(response)) => response.status().is_success(),
            _ => false,
        }
    }

    /// 更新后端服务器健康状态
    pub async fn update_backend_health(&self, domain: &str, backend_host: &str, is_healthy: bool) {
        let mut sites = self.sites.write().await;

        if let Some(site) = sites.get_mut(domain) {
            for backend in &mut site.backends {
                if backend.host == backend_host {
                    backend.is_healthy = is_healthy;
                    break;
                }
            }
        }
    }

    /// 获取所有网站配置
    pub async fn get_all_sites(&self) -> Vec<(String, SiteConfig)> {
        let sites = self.sites.read().await;
        sites.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// 获取转发统计信息
    pub async fn get_forward_stats(&self) -> ForwardStats {
        let sites = self.sites.read().await;
        let total_sites = sites.len();
        let enabled_sites = sites.values().filter(|s| s.is_enabled).count();
        let total_backends = sites.values().map(|s| s.backends.len()).sum();
        let healthy_backends = sites
            .values()
            .flat_map(|s| &s.backends)
            .filter(|b| b.is_healthy)
            .count();

        ForwardStats {
            total_sites,
            enabled_sites,
            total_backends,
            healthy_backends,
        }
    }
}

/// 转发统计信息
#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardStats {
    pub total_sites: usize,
    pub enabled_sites: usize,
    pub total_backends: usize,
    pub healthy_backends: usize,
}

/// 响应修改服务
#[allow(dead_code)]
pub struct ResponseModifier {
    // 响应修改规则等
}

#[allow(dead_code)]
impl ResponseModifier {
    pub fn new() -> Self {
        Self {}
    }

    /// 修改响应内容
    pub async fn modify_response(
        &self,
        mut response: Response,
        rules: &ResponseModificationRules,
    ) -> Response {
        // 如果需要修改响应头
        if !rules.headers_to_add.is_empty() || !rules.headers_to_remove.is_empty() {
            let (mut parts, body) = response.into_parts();

            // 添加头部
            for (name, value) in &rules.headers_to_add {
                if let (Ok(header_name), Ok(header_value)) = (
                    HeaderName::try_from(name.as_str()),
                    HeaderValue::try_from(value.as_str()),
                ) {
                    parts.headers.insert(header_name, header_value);
                }
            }

            // 移除头部
            for name in &rules.headers_to_remove {
                if let Ok(header_name) = HeaderName::try_from(name.as_str()) {
                    parts.headers.remove(&header_name);
                }
            }

            response = Response::from_parts(parts, body);
        }

        response
    }

    /// 注入安全头部
    pub async fn inject_security_headers(&self, response: Response) -> Response {
        let (mut parts, body) = response.into_parts();

        // 添加安全相关头部
        let security_headers = [
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-XSS-Protection", "1; mode=block"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ];

        for (name, value) in security_headers {
            if let (Ok(header_name), Ok(header_value)) =
                (HeaderName::try_from(name), HeaderValue::try_from(value))
            {
                parts.headers.insert(header_name, header_value);
            }
        }

        Response::from_parts(parts, body)
    }
}

/// 响应修改规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseModificationRules {
    pub headers_to_add: HashMap<String, String>,
    pub headers_to_remove: Vec<String>,
    pub inject_security_headers: bool,
    pub body_modifications: Vec<BodyModification>,
}

impl Default for ResponseModificationRules {
    fn default() -> Self {
        Self {
            headers_to_add: HashMap::new(),
            headers_to_remove: Vec::new(),
            inject_security_headers: true,
            body_modifications: Vec::new(),
        }
    }
}

/// 响应体修改规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyModification {
    pub pattern: String,
    pub replacement: String,
    pub is_regex: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forward_service_creation() {
        let service = ForwardService::new();
        let stats = service.get_forward_stats().await;

        assert_eq!(stats.total_sites, 0);
        assert_eq!(stats.enabled_sites, 0);
    }

    #[tokio::test]
    async fn test_site_config_management() {
        let service = ForwardService::new();

        let backend = BackendServer {
            host: "127.0.0.1".to_string(),
            port: 8080,
            protocol: "http".to_string(),
            weight: 1,
            health_check_path: "/health".to_string(),
            is_healthy: true,
        };

        let config = SiteConfig {
            domain: "example.com".to_string(),
            backends: vec![backend],
            forward_config: ForwardConfig::default(),
            is_enabled: true,
        };

        // 添加网站配置
        service
            .update_site_config("example.com".to_string(), config)
            .await;

        // 检查网站是否启用
        assert!(service.is_site_enabled("example.com").await);
        assert!(!service.is_site_enabled("nonexistent.com").await);

        // 获取网站配置
        let retrieved = service.get_site_config("example.com").await;
        assert!(retrieved.is_some());

        // 删除网站配置
        assert!(service.remove_site_config("example.com").await);
        assert!(!service.remove_site_config("nonexistent.com").await);
    }

    #[test]
    fn test_backend_server_url() {
        let backend = BackendServer {
            host: "127.0.0.1".to_string(),
            port: 8080,
            protocol: "https".to_string(),
            weight: 1,
            health_check_path: "/health".to_string(),
            is_healthy: true,
        };

        assert_eq!(backend.get_base_url(), "https://127.0.0.1:8080");
    }
}
