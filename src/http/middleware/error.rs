use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::{Request, Response, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::BoxError;
use serde_json::json;
use tower::{Layer, Service};
use tracing::error;

use crate::core::error::AppError;

/// HTTP错误类型
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("请求无效: {0}")]
    BadRequest(String),

    #[error("未授权: {0}")]
    Unauthorized(String),

    #[error("禁止访问: {0}")]
    #[allow(dead_code)]
    Forbidden(String),

    #[error("资源不存在: {0}")]
    #[allow(dead_code)]
    NotFound(String),

    #[error("请求超时: {0}")]
    #[allow(dead_code)]
    Timeout(String),

    #[error("内部服务器错误: {0}")]
    #[allow(dead_code)]
    InternalServerError(String),

    #[error("内部服务器错误: {0}")]
    Internal(String),

    #[error("网关错误: {0}")]
    #[allow(dead_code)]
    BadGateway(String),

    #[error("服务不可用: {0}")]
    #[allow(dead_code)]
    ServiceUnavailable(String),
}

impl HttpError {
    /// 获取对应的HTTP状态码
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            Self::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// 从AppError转换为HttpError
impl From<AppError> for HttpError {
    fn from(err: AppError) -> Self {
        match err {
            AppError::Http(msg) => HttpError::Internal(msg),
            AppError::Config(msg) => HttpError::Internal(format!("配置错误: {msg}")),
            AppError::Cache(msg) => HttpError::Internal(format!("缓存错误: {msg}")),
            AppError::RuleEngine(msg) => HttpError::Internal(format!("规则引擎错误: {msg}")),
            AppError::Grpc(msg) => HttpError::Internal(format!("gRPC错误: {msg}")),
            AppError::Captcha(msg) => HttpError::BadRequest(format!("验证码错误: {msg}")),
            AppError::Identity(msg) => HttpError::Unauthorized(format!("身份识别错误: {msg}")),
            AppError::Database(msg) => HttpError::Internal(format!("数据库错误: {msg}")),
            AppError::Serialization(msg) => HttpError::BadRequest(format!("序列化错误: {msg}")),
            AppError::NotFound(msg) => HttpError::NotFound(format!("未找到: {msg}")),
            AppError::ValidationError(msg) => HttpError::BadRequest(format!("验证错误: {msg}")),
            AppError::Io(err) => HttpError::Internal(format!("IO错误: {err}")),
            AppError::Unknown(msg) => HttpError::Internal(format!("未知错误: {msg}")),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response<axum::body::Body> {
        let status = self.status_code();
        let body = Json(json!({
            "error": {
                "code": status.as_u16(),
                "message": self.to_string(),
            }
        }));

        (status, body).into_response()
    }
}

/// 错误处理中间件层
#[derive(Clone)]
pub struct ErrorHandlingLayer;

impl ErrorHandlingLayer {
    #[allow(dead_code)]
    pub fn new() -> Self {
        ErrorHandlingLayer {}
    }
}

/// 错误处理中间件服务实现
#[derive(Clone)]
pub struct ErrorHandlingService<S> {
    inner: S,
}

impl<S> Layer<S> for ErrorHandlingLayer {
    type Service = ErrorHandlingService<S>;

    fn layer(&self, service: S) -> Self::Service {
        ErrorHandlingService { inner: service }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for ErrorHandlingService<S>
where
    S: Service<Request<ReqBody>, Error = BoxError> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<axum::body::Body>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match inner.call(req).await {
                Ok(response) => {
                    // 将响应转换为标准响应
                    let response = response.into_response();

                    // 检查响应状态码
                    let status = response.status();
                    if status.is_server_error() {
                        // 记录服务器错误
                        error!("服务器错误: 状态码 {}", status.as_u16());
                    }

                    // 返回响应
                    Ok(response)
                }
                Err(err) => {
                    // 记录错误
                    error!("请求处理错误: {}", err);

                    // 返回通用错误响应
                    let error_response =
                        HttpError::Internal(format!("内部服务器错误: {err}")).into_response();

                    Ok(error_response)
                }
            }
        })
    }
}

/// 创建错误响应
pub fn error_response(status: StatusCode, message: &str) -> Response<axum::body::Body> {
    let body = Json(json!({
        "error": {
            "code": status.as_u16(),
            "message": message,
        }
    }));

    (status, body).into_response()
}

/// 创建通用的500错误响应
#[allow(dead_code)]
pub fn internal_error<E>(err: E) -> Response<axum::body::Body>
where
    E: std::fmt::Display,
{
    error!("内部服务器错误: {}", err);
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("内部服务器错误: {err}"),
    )
}

/// 创建通用的404错误响应
pub fn not_found_error(resource: &str) -> Response<axum::body::Body> {
    error_response(StatusCode::NOT_FOUND, &format!("资源不存在: {resource}"))
}

/// 创建通用的400错误响应
#[allow(dead_code)]
pub fn bad_request_error(message: &str) -> Response<axum::body::Body> {
    error_response(StatusCode::BAD_REQUEST, &format!("请求无效: {message}"))
}
