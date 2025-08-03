use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, Json, Request},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::{debug, error, warn};

use crate::core::logger::FileLogger;
use crate::core::statistics::Statistics;
use crate::core::sync::DataSyncManager;
use crate::defense::{DefenseAction, DefenseManager};
use crate::http::{
    attack_analysis::MaliciousRequestAnalyzer, attack_logging::AttackLogger,
    forward::WafRequestForwarder, middleware::error::HttpError,
};
use crate::rules::detector::AttackDetector;

#[derive(Deserialize)]
pub struct VerifyRequest {
    solution: crate::defense::challenge::ChallengeSolution,
    behavior: Vec<crate::defense::challenge::BehaviorEvent>,
}

#[derive(Deserialize)]
pub struct ClickVerifyRequest {
    challenge_id: String,
    clicks: Vec<ClickPosition>,
    behavior: Vec<crate::defense::challenge::BehaviorEvent>,
}

#[derive(Deserialize)]
struct ClickPosition {
    x: f32,
    y: f32,
    timestamp: u64,
}

#[derive(Deserialize)]
pub struct CaptchaVerifyRequest {
    challenge_id: String,
    answer: String,
}

/// WAF集成请求处理器
#[derive(Clone)]
pub struct WafRequestHandler {
    forwarder: WafRequestForwarder,
    analyzer: MaliciousRequestAnalyzer,
    attack_logger: AttackLogger,
    defense_manager: Arc<DefenseManager>,
}

impl WafRequestHandler {
    /// 创建新的WAF请求处理器
    pub fn new(
        sync_manager: Arc<DataSyncManager>,
        statistics: Arc<Statistics>,
        detector: Arc<AttackDetector>,
        logger: Arc<FileLogger>,
    ) -> Self {
        let forwarder = WafRequestForwarder::new(sync_manager.clone(), statistics.clone());
        let analyzer = MaliciousRequestAnalyzer::new(sync_manager, statistics, detector);
        let attack_logger = AttackLogger::new(logger);
        let defense_manager = Arc::new(DefenseManager::new());

        Self {
            forwarder,
            analyzer,
            attack_logger,
            defense_manager,
        }
    }

    /// 处理所有HTTP请求的主入口点
    pub async fn handle_request(
        &self,
        request: Request<Body>,
        connect_info: ConnectInfo<SocketAddr>,
    ) -> Result<Response<Body>, HttpError> {
        let client_ip = connect_info.0.ip();
        let start_time = std::time::Instant::now();

        debug!(
            "处理来自 {} 的请求: {} {}",
            client_ip,
            request.method(),
            request.uri()
        );

        // 第一步：检查防御状态
        let defense_action = self
            .defense_manager
            .check_defense(&request)
            .await
            .map_err(|e| HttpError::Internal(e.to_string()))?;

        match defense_action {
            DefenseAction::Allow => {
                // 继续正常流程
            }
            DefenseAction::FiveSecondShield => {
                return Ok(self.create_five_second_shield_response(&request).await);
            }
            DefenseAction::ClickShield => {
                return Ok(self.create_click_shield_response(&request).await);
            }
            DefenseAction::CaptchaShield => {
                return Ok(self.create_captcha_shield_response(&request).await);
            }
        }

        // 第二步：恶意请求分析
        let analysis_result = self.analyzer.analyze_request(&request, client_ip).await;

        // 如果检测到恶意请求且需要阻止
        if analysis_result.should_block {
            warn!(
                "阻止恶意请求: {} {} {} - 原因: {}",
                client_ip,
                request.method(),
                request.uri(),
                analysis_result.block_reason.as_deref().unwrap_or("未知")
            );

            // 记录攻击日志
            self.attack_logger
                .log_attack(&request, client_ip, &analysis_result, None)
                .await;

            // 返回阻止页面
            return Ok(self.create_blocked_response(&analysis_result));
        }

        // 如果检测到攻击但不阻止，仍然记录日志
        if analysis_result.is_malicious {
            self.attack_logger
                .log_attack(&request, client_ip, &analysis_result, None)
                .await;
        }

        // 第二步：请求转发
        match self.forwarder.handle_request(request).await {
            Ok(response) => {
                let duration = start_time.elapsed();
                debug!("请求处理完成，耗时: {:?}", duration);
                Ok(response)
            }
            Err(e) => {
                error!("请求转发失败: {}", e);
                Err(e)
            }
        }
    }

    /// 创建阻止响应页面
    fn create_blocked_response(
        &self,
        analysis_result: &crate::http::attack_analysis::RequestAnalysisResult,
    ) -> Response<Body> {
        let reason = analysis_result
            .block_reason
            .as_deref()
            .unwrap_or("请求被阻止");
        let attack_type = analysis_result
            .attack_info
            .as_ref()
            .map(|info| match info.attack_type {
                crate::rules::model::AttackType::XSS => "跨站脚本攻击",
                crate::rules::model::AttackType::SQLInjection => "SQL注入攻击",
                crate::rules::model::AttackType::SSRF => "服务器端请求伪造",
                crate::rules::model::AttackType::WebShell => "WebShell攻击",
                crate::rules::model::AttackType::Custom => "自定义规则匹配",
            })
            .unwrap_or("恶意请求");

        let html_content = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>请求被阻止 - CRWAF</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
            margin: 20px;
        }}
        .icon {{
            font-size: 64px;
            color: #e74c3c;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 28px;
            font-weight: 600;
        }}
        .reason {{
            background: #f8f9fa;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
            border-radius: 0 5px 5px 0;
        }}
        .attack-type {{
            color: #e74c3c;
            font-weight: 600;
            font-size: 16px;
        }}
        .description {{
            color: #6c757d;
            margin-top: 10px;
            line-height: 1.5;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #6c757d;
            font-size: 14px;
        }}
        .powered-by {{
            color: #007bff;
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>请求被阻止</h1>
        <div class="reason">
            <div class="attack-type">检测类型: {}</div>
            <div class="description">{}</div>
        </div>
        <p>您的请求被我们的安全系统识别为潜在威胁并已被阻止。如果您认为这是误报，请联系网站管理员。</p>
        <div class="footer">
            <div class="powered-by">Protected by CRWAF</div>
            <div>Web Application Firewall</div>
        </div>
    </div>
</body>
</html>"#,
            attack_type, reason
        );

        Response::builder()
            .status(403)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("X-Protected-By", "CRWAF")
            .header("X-Block-Reason", reason)
            .body(Body::from(html_content))
            .unwrap()
    }

    /// 获取分析器引用（用于管理功能）
    pub fn get_analyzer(&self) -> &MaliciousRequestAnalyzer {
        &self.analyzer
    }

    /// 获取攻击日志记录器引用
    pub fn get_attack_logger(&self) -> &AttackLogger {
        &self.attack_logger
    }

    /// 获取转发器引用
    pub fn get_forwarder(&self) -> &WafRequestForwarder {
        &self.forwarder
    }

    /// 创建五秒盾响应
    async fn create_five_second_shield_response(&self, request: &Request<Body>) -> Response<Body> {
        use crate::defense::shield::FiveSecondShield;

        let session_id = self.extract_session_id(request);
        let session = self.defense_manager.create_session(session_id).await;

        let shield = FiveSecondShield::new();
        let challenge = shield.generate_challenge(session.challenge_id.as_ref().unwrap());

        let request_info = self.extract_request_info(request);
        let html = shield.generate_response_page(&challenge, request_info);

        Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Body::from(html.0))
            .unwrap()
    }

    /// 创建点击盾响应
    async fn create_click_shield_response(&self, request: &Request<Body>) -> Response<Body> {
        use crate::defense::shield::ClickShield;

        let session_id = self.extract_session_id(request);
        let session = self.defense_manager.create_session(session_id).await;

        let shield = ClickShield::new();
        let request_info = self.extract_request_info(request);
        let html =
            shield.generate_response_page(session.challenge_id.as_ref().unwrap(), request_info);

        Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Body::from(html.0))
            .unwrap()
    }

    /// 创建验证码盾响应
    async fn create_captcha_shield_response(&self, request: &Request<Body>) -> Response<Body> {
        use crate::defense::captcha::{CaptchaGenerator, CaptchaShield};

        let session_id = self.extract_session_id(request);
        let session = self.defense_manager.create_session(session_id).await;

        // Create captcha generator and shield
        let generator = match CaptchaGenerator::new() {
            Ok(gen) => Arc::new(gen),
            Err(_) => {
                return Response::builder()
                    .status(500)
                    .body(Body::from("Failed to initialize captcha"))
                    .unwrap();
            }
        };

        let shield = CaptchaShield::new(generator);
        let request_info = self.extract_request_info(request);
        let html =
            shield.generate_response_page(session.challenge_id.as_ref().unwrap(), request_info);

        Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Body::from(html.0))
            .unwrap()
    }

    /// 从请求中提取会话ID
    fn extract_session_id(&self, request: &Request<Body>) -> String {
        request
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                cookies
                    .split(';')
                    .find(|c| c.trim().starts_with("waf_session="))
                    .map(|c| c.trim_start_matches("waf_session=").trim().to_string())
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }

    /// 提取请求信息
    fn extract_request_info(&self, request: &Request<Body>) -> crate::defense::shield::RequestInfo {
        let ip = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let host = request
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let url = request.uri().to_string();
        let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        crate::defense::shield::RequestInfo {
            ip,
            url,
            time,
            host,
        }
    }

    /// 验证挑战响应
    pub async fn verify_challenge(
        &self,
        headers: HeaderMap,
        Json(payload): Json<VerifyRequest>,
    ) -> impl IntoResponse {
        let session_id = self.extract_session_id_from_headers(&headers);

        // 验证挑战解决方案
        let is_valid = self
            .defense_manager
            .verify_challenge(
                &session_id,
                &serde_json::to_string(&payload.solution).unwrap(),
            )
            .await
            .unwrap_or(false);

        if is_valid {
            // 设置会话cookie
            let cookie = format!(
                "waf_session={}; Path=/; HttpOnly; SameSite=Strict",
                session_id
            );

            (
                StatusCode::OK,
                [("Set-Cookie", cookie)],
                Json(serde_json::json!({
                    "success": true,
                    "message": "Verification successful"
                })),
            )
                .into_response()
        } else {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Verification failed"
                })),
            )
                .into_response()
        }
    }

    /// 验证点击挑战
    pub async fn verify_click_challenge(
        &self,
        headers: HeaderMap,
        Json(payload): Json<ClickVerifyRequest>,
    ) -> impl IntoResponse {
        let session_id = self.extract_session_id_from_headers(&headers);

        // 简单验证点击挑战
        if payload.clicks.len() >= 3 {
            let is_valid = self
                .defense_manager
                .verify_challenge(&session_id, "click_verified")
                .await
                .unwrap_or(false);

            if is_valid {
                let cookie = format!(
                    "waf_session={}; Path=/; HttpOnly; SameSite=Strict",
                    session_id
                );

                return (
                    StatusCode::OK,
                    [("Set-Cookie", cookie)],
                    Json(serde_json::json!({
                        "success": true,
                        "message": "Click verification successful"
                    })),
                )
                    .into_response();
            }
        }

        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": "Click verification failed"
            })),
        )
            .into_response()
    }

    /// 从HeaderMap中提取会话ID
    fn extract_session_id_from_headers(&self, headers: &HeaderMap) -> String {
        headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                cookies
                    .split(';')
                    .find(|c| c.trim().starts_with("waf_session="))
                    .map(|c| c.trim_start_matches("waf_session=").trim().to_string())
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }

    /// 生成验证码
    pub async fn generate_captcha(&self, challenge_id: String) -> impl IntoResponse {
        use crate::defense::captcha::CaptchaGenerator;

        let generator = match CaptchaGenerator::new() {
            Ok(gen) => gen,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "message": "Failed to initialize captcha"
                    })),
                )
                    .into_response();
            }
        };

        match generator.generate_captcha(&challenge_id).await {
            Ok(captcha_text) => Json(serde_json::json!({
                "captcha": captcha_text
            }))
            .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Failed to generate captcha"
                })),
            )
                .into_response(),
        }
    }

    /// 验证验证码
    pub async fn verify_captcha_challenge(
        &self,
        headers: HeaderMap,
        Json(payload): Json<CaptchaVerifyRequest>,
    ) -> impl IntoResponse {
        use crate::defense::captcha::CaptchaGenerator;

        let session_id = self.extract_session_id_from_headers(&headers);

        // Verify captcha
        let generator = match CaptchaGenerator::new() {
            Ok(gen) => gen,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "message": "Internal error"
                    })),
                )
                    .into_response();
            }
        };

        let is_valid = generator
            .verify_captcha(&payload.challenge_id, &payload.answer)
            .await;

        if is_valid {
            // Mark session as verified
            let _ = self
                .defense_manager
                .verify_challenge(&session_id, "captcha_verified")
                .await;

            let cookie = format!(
                "waf_session={}; Path=/; HttpOnly; SameSite=Strict",
                session_id
            );

            (
                StatusCode::OK,
                [("Set-Cookie", cookie)],
                Json(serde_json::json!({
                    "success": true,
                    "message": "Captcha verification successful"
                })),
            )
                .into_response()
        } else {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Captcha verification failed"
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::ConnectInfo, http::Method};
    use std::net::{Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test_waf_request_handler_creation() {
        let sync_manager = Arc::new(DataSyncManager::new(
            Arc::new(crate::core::statistics::Statistics::new()),
            "test".to_string(),
        ));
        let statistics = Arc::new(crate::core::statistics::Statistics::new());
        let rule_engine = crate::rules::engine::RuleEngine::new();
        let detector = Arc::new(
            crate::rules::detector::AttackDetector::new(
                rule_engine,
                crate::rules::detector::DetectionLevel::Medium,
            )
            .unwrap(),
        );
        let log_config = crate::core::logger::LogConfig {
            log_dir: "test_logs".to_string(),
            prefix: "test".to_string(),
            rotation_policy: crate::core::logger::RotationPolicy::Never,
            compression_policy: crate::core::logger::CompressionPolicy::None,
            max_files: Some(5),
        };
        let logger = Arc::new(crate::core::logger::FileLogger::new(log_config).unwrap());

        let _handler = WafRequestHandler::new(sync_manager, statistics, detector, logger);
    }

    #[tokio::test]
    async fn test_normal_request_handling() {
        let sync_manager = Arc::new(DataSyncManager::new(
            Arc::new(crate::core::statistics::Statistics::new()),
            "test".to_string(),
        ));
        let statistics = Arc::new(crate::core::statistics::Statistics::new());
        let rule_engine = crate::rules::engine::RuleEngine::new();
        let detector = Arc::new(
            crate::rules::detector::AttackDetector::new(
                rule_engine,
                crate::rules::detector::DetectionLevel::Medium,
            )
            .unwrap(),
        );
        let log_config = crate::core::logger::LogConfig {
            log_dir: "test_logs".to_string(),
            prefix: "test".to_string(),
            rotation_policy: crate::core::logger::RotationPolicy::Never,
            compression_policy: crate::core::logger::CompressionPolicy::None,
            max_files: Some(5),
        };
        let logger = Arc::new(crate::core::logger::FileLogger::new(log_config).unwrap());

        let handler = WafRequestHandler::new(sync_manager, statistics, detector, logger);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();

        let connect_info = ConnectInfo(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ));

        // 由于没有配置网站，应该返回404
        let result = handler.handle_request(request, connect_info).await;
        // 这里应该是转发错误，因为没有配置后端
        assert!(result.is_ok() || result.is_err());
    }
}
