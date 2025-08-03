use std::fmt;
use std::io;

use thiserror::Error;

/// 应用程序错误类型
#[derive(Debug, Error)]
pub enum AppError {
    #[error("IO错误: {0}")]
    Io(#[from] io::Error),
    
    #[error("配置错误: {0}")]
    Config(String),
    
    #[error("缓存错误: {0}")]
    Cache(String),
    
    #[error("规则引擎错误: {0}")]
    RuleEngine(String),
    
    #[error("HTTP错误: {0}")]
    Http(String),
    
    #[error("gRPC错误: {0}")]
    Grpc(String),
    
    #[allow(dead_code)]
    #[error("验证码错误: {0}")]
    Captcha(String),
    
    #[allow(dead_code)]
    #[error("身份识别错误: {0}")]
    Identity(String),
    
    #[allow(dead_code)]
    #[error("数据库错误: {0}")]
    Database(String),
    
    #[error("序列化错误: {0}")]
    Serialization(String),
    
    #[error("未知错误: {0}")]
    Unknown(String),
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Unknown(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Serialization(err.to_string())
    }
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        AppError::Config(err.to_string())
    }
}

/// 结果类型别名
#[allow(dead_code)]
pub type AppResult<T> = Result<T, AppError>;

/// 错误处理工具函数
pub mod utils {
    use super::*;
    use tracing::{error, warn};
    
    /// 记录错误并返回
    #[allow(dead_code)]
    pub fn log_error<E: fmt::Display>(err: E) -> String {
        let err_msg = err.to_string();
        error!("错误: {}", err_msg);
        err_msg
    }
    
    /// 记录警告并返回
    #[allow(dead_code)]
    pub fn log_warning<E: fmt::Display>(err: E) -> String {
        let err_msg = err.to_string();
        warn!("警告: {}", err_msg);
        err_msg
    }
    
    /// 将错误转换为AppError::Config
    #[allow(dead_code)]
    pub fn config_err<E: fmt::Display>(err: E) -> AppError {
        AppError::Config(err.to_string())
    }
    
    /// 将错误转换为AppError::Cache
    #[allow(dead_code)]
    pub fn cache_err<E: fmt::Display>(err: E) -> AppError {
        AppError::Cache(err.to_string())
    }
    
    /// 将错误转换为AppError::RuleEngine
    #[allow(dead_code)]
    pub fn rule_engine_err<E: fmt::Display>(err: E) -> AppError {
        AppError::RuleEngine(err.to_string())
    }
    
    /// 将错误转换为AppError::Http
    #[allow(dead_code)]
    pub fn http_err<E: fmt::Display>(err: E) -> AppError {
        AppError::Http(err.to_string())
    }
    
    /// 将错误转换为AppError::Grpc
    #[allow(dead_code)]
    pub fn grpc_err<E: fmt::Display>(err: E) -> AppError {
        AppError::Grpc(err.to_string())
    }
}