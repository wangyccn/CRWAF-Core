use std::task::{Context, Poll};
use std::time::Instant;

use axum::http::{Request, Response};
use tower::{Layer, Service};
use tracing::{info, warn};

/// 日志中间件层
#[derive(Clone)]
pub struct LoggingLayer;

impl LoggingLayer {
    pub fn new() -> Self {
        LoggingLayer {}
    }
}

/// 日志中间件服务实现
#[derive(Clone)]
pub struct LoggingService<S> {
    inner: S,
}

impl<S> Layer<S> for LoggingLayer {
    type Service = LoggingService<S>;

    fn layer(&self, service: S) -> Self::Service {
        LoggingService { inner: service }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for LoggingService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Debug,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // 克隆服务以便在异步闭包中使用
        let mut inner = self.inner.clone();

        // 记录请求开始时间
        let start = Instant::now();

        // 提取请求信息
        let method = req.method().clone();
        let uri = req.uri().clone();
        let version = req.version();

        // 获取客户端IP
        let client_ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        // 记录请求日志
        info!(
            "请求开始: {} {} {:?} 来自 {}",
            method, uri, version, client_ip
        );

        // 处理请求并记录响应
        Box::pin(async move {
            let result = inner.call(req).await;

            match &result {
                Ok(response) => {
                    // 计算处理时间
                    let duration = start.elapsed();

                    // 记录响应日志
                    info!(
                        "请求完成: {} {} - 状态码: {} - 耗时: {:?}",
                        method,
                        uri,
                        response.status(),
                        duration
                    );
                }
                Err(e) => {
                    // 记录错误日志
                    warn!("请求错误: {} {} - 错误: {:?}", method, uri, e);
                }
            }

            result
        })
    }
}
