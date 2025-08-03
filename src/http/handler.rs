use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use serde_json::json;

use crate::core::error::AppError;
use crate::http::middleware::error::{HttpError, error_response, not_found_error};

use crate::core::config::AppConfig;

/// 首页处理器
pub async fn index() -> Html<&'static str> {
    Html("<h1>CRWAF - 云锁Web应用防火墙</h1><p>系统正在运行中</p>")
}

/// 健康检查处理器
pub async fn health_check(State(config): State<Arc<AppConfig>>) -> impl IntoResponse {
    let status = json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "server": {
            "host": &config.server.host,
            "port": config.server.port,
        }
    });

    (StatusCode::OK, Json(status))
}

/// 处理404错误
pub async fn handle_404() -> impl IntoResponse {
    not_found_error("请求的资源不存在")
}

/// 处理错误示例
pub async fn error_example() -> Result<(StatusCode, Json<serde_json::Value>), HttpError> {
    // 模拟错误情况
    Err(HttpError::BadRequest("这是一个错误示例".to_string()))
}

/// 处理内部错误示例
pub async fn internal_error_example() -> impl IntoResponse {
    // 模拟内部错误
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "内部服务器错误示例")
}

/// 处理AppError示例
pub async fn app_error_example() -> Result<(StatusCode, Json<serde_json::Value>), HttpError> {
    // 模拟AppError
    let app_error = AppError::Config("配置加载失败".to_string());
    
    // 将AppError转换为HttpError
    Err(app_error.into())
}

/// 处理IO错误示例
pub async fn io_error_example() -> Result<impl IntoResponse, HttpError> {
    // 模拟IO错误
    let io_result = std::fs::read_to_string("不存在的文件.txt");
    
    match io_result {
        Ok(content) => Ok((StatusCode::OK, content)),
        Err(io_error) => {
            // 将IO错误转换为AppError，再转换为HttpError
            let app_error: AppError = io_error.into();
            Err(app_error.into())
        }
    }
}