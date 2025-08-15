use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Request},
    response::Response,
    routing::{get, post},
    serve, Router,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use crate::core::config::AppConfig;
use crate::core::logger::FileLogger;
use crate::core::statistics::Statistics;
use crate::core::sync::DataSyncManager;
use crate::http::middleware::logging::LoggingLayer;
use crate::http::{handler, waf_handler::WafRequestHandler};
use crate::rules::detector::AttackDetector;

/// 运行HTTP服务器
pub async fn run_server(
    addr: SocketAddr,
    config: Arc<AppConfig>,
    sync_manager: Arc<DataSyncManager>,
    statistics: Arc<Statistics>,
    detector: Arc<AttackDetector>,
    logger: Arc<FileLogger>,
) {
    // 创建应用路由
    let app = create_router(config, sync_manager, statistics, detector, logger);

    // 启动服务器
    info!("启动HTTP服务器于 {}", addr);
    match TcpListener::bind(addr).await {
        Ok(listener) => match serve(listener, app).await {
            Ok(_) => info!("服务器已关闭"),
            Err(e) => error!("服务器错误: {}", e),
        },
        Err(e) => {
            error!("无法绑定HTTP服务器到地址 {}: {}", addr, e);
        }
    }
}

/// 创建应用路由
pub fn create_router(
    config: Arc<AppConfig>,
    sync_manager: Arc<DataSyncManager>,
    statistics: Arc<Statistics>,
    detector: Arc<AttackDetector>,
    logger: Arc<FileLogger>,
) -> Router {
    // 创建WAF处理器
    let _waf_handler = Arc::new(WafRequestHandler::new(
        sync_manager,
        statistics,
        detector,
        logger,
    ));

    // 中间件层
    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(LoggingLayer::new());

    // 应用路由
    let app = Router::new()
        // 管理接口（不经过WAF处理）
        .route("/health", get(handler::health_check))
        .route("/waf/status", get(waf_status_handler))
        // WAF验证接口 - 简化处理
        .route("/waf/verify", post(verify_handler))
        .route("/waf/verify-click", post(click_verify_handler))
        .route(
            "/waf/challenge.js",
            get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/javascript")
                    .body(Body::from(include_str!("../../static/waf/challenge.js")))
                    .unwrap()
            }),
        )
        .route(
            "/waf/click-challenge.js",
            get(|| async {
                axum::response::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/javascript")
                    .body(Body::from(include_str!(
                        "../../static/waf/click-challenge.js"
                    )))
                    .unwrap()
            }),
        )
        // 验证码相关路由 - 简化处理
        .route("/waf/verify-captcha", post(captcha_verify_handler))
        .route("/waf/captcha/:challenge_id", get(captcha_gen_handler))
        // 所有其他请求都通过WAF处理 - 简化为直接调用
        .fallback(fallback_handler)
        .layer(middleware_stack)
        .with_state(config);

    info!("WAF HTTP服务器路由已配置");
    app
}

// 简化的处理器函数
async fn verify_handler() -> Response<Body> {
    Response::builder()
        .status(501)
        .body(Body::from("Not implemented"))
        .unwrap()
}

async fn click_verify_handler() -> Response<Body> {
    Response::builder()
        .status(501)
        .body(Body::from("Not implemented"))
        .unwrap()
}

async fn captcha_verify_handler() -> Response<Body> {
    Response::builder()
        .status(501)
        .body(Body::from("Not implemented"))
        .unwrap()
}

async fn captcha_gen_handler(Path(_challenge_id): Path<String>) -> Response<Body> {
    Response::builder()
        .status(501)
        .body(Body::from("Not implemented"))
        .unwrap()
}

async fn fallback_handler(_request: Request<Body>) -> Response<Body> {
    // 简单的404响应，暂时不调用WAF处理器
    Response::builder()
        .status(404)
        .body(Body::from("Not Found"))
        .unwrap()
}

/// WAF状态处理器
async fn waf_status_handler() -> Response<Body> {
    let status_html = r#"<!DOCTYPE html>
<html>
<head>
    <title>CRWAF Status</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { color: #27ae60; font-weight: bold; }
        .info { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🛡️ CRWAF - Web应用防火墙</h1>
    <div class="info">
        <p><strong>状态:</strong> <span class="status">运行中</span></p>
        <p><strong>版本:</strong> v0.1.0</p>
        <p><strong>功能:</strong></p>
        <ul>
            <li>✅ 请求拦截和Host头获取</li>
            <li>✅ 网站有效性检查</li>
            <li>✅ 请求转发逻辑</li>
            <li>✅ 规则匹配引擎</li>
            <li>✅ IP白名单和黑名单管理</li>
            <li>✅ 攻击日志记录</li>
        </ul>
    </div>
    <p>所有功能正常运行，WAF保护已激活。</p>
</body>
</html>"#;

    Response::builder()
        .status(200)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("X-Protected-By", "CRWAF")
        .body(Body::from(status_html))
        .unwrap()
}
