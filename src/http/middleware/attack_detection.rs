use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use futures::future::BoxFuture;
use futures::FutureExt;
use tower::{Layer, Service};
use tracing::{error, warn};

use crate::rules::detector::AttackDetector;

/// 攻击检测中间件层
#[derive(Clone)]
pub struct AttackDetectionLayer {
    detector: Arc<Mutex<AttackDetector>>,
}

impl AttackDetectionLayer {
    /// 创建新的攻击检测中间件层
    pub fn new(detector: Arc<Mutex<AttackDetector>>) -> Self {
        Self { detector }
    }
}

impl<S> Layer<S> for AttackDetectionLayer {
    type Service = AttackDetectionMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AttackDetectionMiddleware {
            inner: service,
            detector: self.detector.clone(),
        }
    }
}

/// 攻击检测中间件
pub struct AttackDetectionMiddleware<S> {
    inner: S,
    detector: Arc<Mutex<AttackDetector>>,
}

impl<S> Service<Request<Body>> for AttackDetectionMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let detector = self.detector.clone();
        let uri = req.uri().to_string();
        let method = req.method().to_string();
        let headers = req.headers().clone();

        // 克隆内部服务
        let mut inner = self.inner.clone();

        async move {
            // 检测URI中的攻击
            let uri_attack = {
                // 获取检测器的锁，并在此作用域结束时自动释放
                match detector.lock() {
                    Ok(guard) => {
                        // 检测URI中的攻击
                        let uri_results = guard.detect_all(&uri);
                        uri_results.into_iter().find(|result| result.detected)
                            .map(|result| result.attack_type.unwrap_or_else(|| "Unknown".to_string()))
                    },
                    Err(_) => {
                        error!("获取检测器锁失败");
                        None
                    }
                }
            };
            
            // 如果获取锁失败，继续处理请求
            if detector.lock().is_err() {
                return inner.call(req).await;
            }
            
            // 如果检测到URI攻击，直接返回
            if let Some(attack_type) = uri_attack {
                warn!("检测到URI中的攻击: {}, URI: {}", attack_type, uri);
                return Ok(create_attack_response(&attack_type));
            }

            // 检测请求头中的攻击
            let header_attack = {
                // 再次获取检测器的锁
                match detector.lock() {
                    Ok(guard) => {
                        // 检查所有请求头
                        let mut attack_info = None;
                        'header_loop: for (name, value) in headers.iter() {
                            if let Ok(value_str) = value.to_str() {
                                let header_results = guard.detect_all(value_str);
                                for result in header_results {
                                    if result.detected {
                                        let attack_type = result.attack_type.unwrap_or_else(|| "Unknown".to_string());
                                        attack_info = Some((attack_type, name.to_string(), value_str.to_string()));
                                        break 'header_loop;
                                    }
                                }
                            }
                        }
                        attack_info
                    },
                    Err(_) => {
                        error!("获取检测器锁失败");
                        None
                    }
                }
            };
            
            // 如果获取锁失败，继续处理请求
            if detector.lock().is_err() {
                return inner.call(req).await;
            }
            
            // 如果检测到请求头攻击，直接返回
            if let Some((attack_type, name, value)) = header_attack {
                warn!("检测到请求头中的攻击: {}, 头: {}, 值: {}", attack_type, name, value);
                return Ok(create_attack_response(&attack_type));
            }

            // 对于POST请求，检测请求体
            if method == "POST" || method == "PUT" || method == "PATCH" {
                // 读取请求体
                let (parts, body) = req.into_parts();
                let bytes = match axum::body::to_bytes(body, 1024 * 1024 * 10).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("读取请求体失败: {}", e);
                        let req = Request::from_parts(parts, Body::empty());
                        return inner.call(req).await;
                    }
                };

                // 检测请求体中的攻击
                if let Ok(body_str) = std::str::from_utf8(&bytes) {
                    let body_attack = {
                        // 再次获取检测器的锁
                        match detector.lock() {
                            Ok(guard) => {
                                let body_results = guard.detect_all(body_str);
                                body_results.into_iter().find(|result| result.detected)
                                    .map(|result| result.attack_type.unwrap_or_else(|| "Unknown".to_string()))
                            },
                            Err(_) => {
                                error!("获取检测器锁失败");
                                None
                            }
                        }
                    };
                    
                    // 如果获取锁失败，继续处理请求
                    if detector.lock().is_err() {
                        let req = Request::from_parts(parts, Body::from(bytes));
                        return inner.call(req).await;
                    }
                    
                    // 如果检测到请求体攻击，直接返回
                    if let Some(attack_type) = body_attack {
                        warn!("检测到请求体中的攻击: {}", attack_type);
                        return Ok(create_attack_response(&attack_type));
                    }
                }

                // 重建请求
                let req = Request::from_parts(parts, Body::from(bytes));
                inner.call(req).await
            } else {
                // 对于其他请求，直接传递
                inner.call(req).await
            }
        }
        .boxed()
    }
}

/// 创建攻击响应
fn create_attack_response(attack_type: &str) -> Response<Body> {
    let message = match attack_type {
        "XSS" => "检测到跨站脚本(XSS)攻击",
        "SQL Injection" => "检测到SQL注入攻击",
        "SSRF" => "检测到服务器端请求伪造(SSRF)攻击",
        "WebShell" => "检测到WebShell攻击",
        _ => "检测到安全攻击",
    };

    let json_response = serde_json::json!({
        "error": "安全警告",
        "message": message,
        "attack_type": attack_type,
        "code": 403
    });

    (StatusCode::FORBIDDEN, axum::Json(json_response)).into_response()
}

// 为了支持克隆内部服务
impl<S> Clone for AttackDetectionMiddleware<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            detector: self.detector.clone(),
        }
    }
}