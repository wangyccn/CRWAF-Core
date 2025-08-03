use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use axum::serve;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use crate::core::config::AppConfig;
use crate::http::handler;
use crate::http::middleware::logging::LoggingLayer;
use crate::http::middleware::error::ErrorHandlingLayer;
use crate::http::middleware::attack_detection::AttackDetectionLayer;
use crate::rules::detector_manager::DetectorManager;

/// 运行HTTP服务器
pub async fn run_server(addr: SocketAddr, config: Arc<AppConfig>) {
    // 创建应用路由
    let app = create_router(config);

    // 启动服务器
    info!("启动HTTP服务器于 {}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    match serve(listener, app).await {
        Ok(_) => info!("服务器已关闭"),
        Err(e) => error!("服务器错误: {}", e),
    }
}

/// 创建应用路由
fn create_router(config: Arc<AppConfig>) -> Router {
    // 中间件层
    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(LoggingLayer::new())
        .layer(ErrorHandlingLayer::new());
        
    // 添加攻击检测中间件（如果检测器可用）
    let app = Router::new()
        .route("/", get(handler::index))
        .route("/health", get(handler::health_check))
        .route("/error-example", get(handler::error_example))
        .route("/internal-error-example", get(handler::internal_error_example))
        .route("/app-error-example", get(handler::app_error_example))
        .route("/io-error-example", get(handler::io_error_example))
        .layer(middleware_stack)
        .fallback(handler::handle_404)
        .with_state(config);
        
    // 获取攻击检测器并添加中间件
    let detector_manager = DetectorManager::global();
    let app = if let Ok(manager) = detector_manager.lock() {
        if let Some(detector) = manager.get_detector() {
            info!("添加攻击检测中间件到HTTP服务器");
            app.layer(AttackDetectionLayer::new(detector))
        } else {
            info!("攻击检测器不可用，HTTP服务器将不使用攻击检测中间件");
            app
        }
    } else {
        info!("无法获取攻击检测管理器锁，HTTP服务器将不使用攻击检测中间件");
        app
    };
    
    // 返回应用
    app
}