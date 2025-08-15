use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod core;
mod defense;
mod http;
mod rules;

/// 解析大小字符串（如 "10MB"、"1GB"）为字节数，避免不必要的分配
fn parse_size(size_str: &str) -> Option<u64> {
    let s = size_str.trim();
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    let num = std::str::from_utf8(&bytes[..idx]).ok()?.parse::<u64>().ok()?;
    let unit = &s[idx..];
    match unit {
        "" => Some(num),
        "kb" | "KB" | "Kb" | "kB" => Some(num * 1024),
        "mb" | "MB" | "Mb" | "mB" => Some(num * 1024 * 1024),
        "gb" | "GB" | "Gb" | "gB" => Some(num * 1024 * 1024 * 1024),
        _ => None,
    }
}

/// 解析时间字符串（如 "24h"、"7d"）为小时数，避免字符串复制
fn parse_time(time_str: &str) -> Option<u64> {
    let s = time_str.trim();
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    let num = std::str::from_utf8(&bytes[..idx]).ok()?.parse::<u64>().ok()?;
    let unit = &s[idx..];
    match unit {
        "" => Some(num),
        "h" | "H" => Some(num),
        "d" | "D" => Some(num * 24),
        "w" | "W" => Some(num * 24 * 7),
        _ => None,
    }
}

async fn run(config: Arc<core::config::AppConfig>) -> Result<()> {

    // 初始化日志系统
    let log_level = match config.log.level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("设置全局日志订阅器失败");

    // 初始化文件日志记录器
    if let Some(log_path) = &config.log.file_path {
        // 创建日志配置
        let log_config = core::logger::LogConfig {
            log_dir: log_path.clone(),
            prefix: config
                .log
                .prefix
                .clone()
                .unwrap_or_else(|| "crwaf".to_string()),
            rotation_policy: match &config.log.rotation_policy {
                Some(policy) if policy.starts_with("size:") => {
                    let size_str = policy.trim_start_matches("size:");
                    let size = parse_size(size_str).unwrap_or(10 * 1024 * 1024); // 默认10MB
                    core::logger::RotationPolicy::Size(size)
                }
                Some(policy) if policy.starts_with("time:") => {
                    let time_str = policy.trim_start_matches("time:");
                    let hours = parse_time(time_str).unwrap_or(24); // 默认24小时
                    core::logger::RotationPolicy::Time(hours)
                }
                Some(policy) if policy == "never" => core::logger::RotationPolicy::Never,
                _ => core::logger::RotationPolicy::Time(24), // 默认24小时
            },
            compression_policy: if config.log.compression.unwrap_or(false) {
                #[cfg(feature = "compression")]
                {
                    core::logger::CompressionPolicy::Gzip
                }
                #[cfg(not(feature = "compression"))]
                {
                    info!("压缩功能未启用，忽略压缩配置");
                    core::logger::CompressionPolicy::None
                }
            } else {
                core::logger::CompressionPolicy::None
            },
            max_files: config.log.max_files,
        };

        // 初始化日志记录器
        match core::logger::FileLogger::new(log_config) {
            Ok(_) => {
                // 存储日志记录器到全局变量或其他地方
                info!("文件日志记录器初始化成功: {}", log_path);
            }
            Err(e) => {
                eprintln!("初始化文件日志记录器失败: {e}");
            }
        }
    }

    info!("CRWAF 正在启动...");

    // 加载配置
    let config = core::config::load_config()?;
    let config = Arc::new(config);

    // 初始化缓存系统
    if config.cache.enabled {
        info!(
            "内存缓存已启用，最大大小: {}, TTL: {}秒",
            config.cache.max_size, config.cache.ttl_seconds
        );

        // 如果启用了文件缓存，初始化文件缓存
        if let Some(file_cache_config) = &config.cache.file_cache {
            if file_cache_config.enabled {
                info!(
                    "文件缓存已启用，目录: {}, TTL: {}秒",
                    file_cache_config.cache_dir, file_cache_config.ttl_seconds
                );

                // 创建文件缓存配置
                let cache_config = core::cache::FileCacheConfig {
                    cache_dir: std::path::PathBuf::from(&file_cache_config.cache_dir),
                    prefix: file_cache_config.prefix.clone(),
                    ttl: std::time::Duration::from_secs(file_cache_config.ttl_seconds),
                    save_interval: file_cache_config.save_interval_seconds,
                    max_items: file_cache_config.max_items,
                };

                // 初始化文件缓存 - 用于规则文件
                match core::cache::FileCache::<
                    String,
                    (
                        crate::rules::parser::RuleFileMeta,
                        Vec<crate::rules::model::Rule>,
                    ),
                >::new(cache_config)
                {
                    Ok(file_cache) => {
                        let file_cache = Arc::new(file_cache);
                        // 启动自动保存任务
                        file_cache.start_auto_save_task();

                        // 将文件缓存实例注册到缓存管理器
                        let cache_manager = core::cache_manager::CacheManager::global();
                        cache_manager.register_file_cache("default", file_cache.clone());

                        info!("文件缓存初始化成功并已注册到缓存管理器");
                    }
                    Err(e) => {
                        eprintln!("初始化文件缓存失败: {e}");
                    }
                }
            }
        }
    }

    // 加载规则引擎
    let mut rule_engine = rules::engine::RuleEngine::new().with_config(config.rules.clone());

    // 使用规则解析器加载规则
    if let Err(e) = rule_engine.load_all_rules() {
        eprintln!("加载规则失败: {e}");
    } else {
        info!("规则引擎初始化成功，已加载规则");
    }

    // 初始化攻击检测器
    let detection_level = rules::detector::DetectionLevel::Medium; // 默认使用中级检测
    match rules::detector::AttackDetector::new(rule_engine, detection_level) {
        Ok(detector) => {
            info!("攻击检测器初始化成功，检测级别: {:?}", detection_level);
            // 将检测器存储到检测器管理器中，以便在HTTP处理中使用
            // 使用Mutex包裹AttackDetector，以支持动态更新检测级别
            let detector_mutex = std::sync::Mutex::new(detector);
            let detector_arc = std::sync::Arc::new(detector_mutex);
            let detector_manager = rules::detector_manager::DetectorManager::global();
            if let Ok(mut manager) = detector_manager.lock() {
                manager.set_detector(detector_arc.clone());
                info!("攻击检测器已注册到检测器管理器");
            } else {
                eprintln!("无法获取检测器管理器锁");
            }
        }
        Err(e) => {
            eprintln!("初始化攻击检测器失败: {e}");
        }
    }

    // 创建统计和同步管理器
    let statistics = Arc::new(core::statistics::Statistics::new());
    let sync_manager = Arc::new(core::sync::DataSyncManager::new(
        statistics.clone(),
        "waf-instance-001".to_string(), // 实例ID
    ));

    // 创建日志器
    let log_config = core::logger::LogConfig {
        log_dir: "logs".to_string(),
        prefix: "crwaf".to_string(),
        rotation_policy: core::logger::RotationPolicy::Time(24),
        compression_policy: core::logger::CompressionPolicy::None,
        max_files: Some(30),
    };

    let logger = match core::logger::FileLogger::new(log_config) {
        Ok(logger) => Arc::new(logger),
        Err(e) => {
            eprintln!("初始化日志器失败: {e}");
            return Err(e.into());
        }
    };

    // 获取攻击检测器
    let rule_engine = rules::engine::RuleEngine::new().with_config(config.rules.clone());

    let detector_arc = match rules::detector::AttackDetector::new(
        rule_engine,
        rules::detector::DetectionLevel::Medium,
    ) {
        Ok(detector) => Arc::new(detector),
        Err(e) => {
            eprintln!("初始化攻击检测器失败: {e}");
            return Err(e.into());
        }
    };

    // 启动HTTP服务器和gRPC服务器
    let http_addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    info!("HTTP服务器监听于 {}", http_addr);

    // 使用tokio spawn启动HTTP服务器
    let http_config = config.clone();
    let http_sync = sync_manager.clone();
    let http_stats = statistics.clone();
    let http_detector = detector_arc.clone();
    let http_logger = logger.clone();
    tokio::spawn(async move {
        http::server::run_server(
            http_addr,
            http_config,
            http_sync,
            http_stats,
            http_detector,
            http_logger,
        )
        .await;
    });

    // 启动gRPC服务器
    let grpc_config = config.clone();
    let grpc_stats = statistics.clone();
    let grpc_sync = sync_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = core::grpc::run_grpc_server(grpc_config, grpc_stats, grpc_sync).await {
            eprintln!("gRPC服务器错误: {e}");
        }
    });

    // 等待中断信号
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("接收到中断信号，正在关闭...");
        }
        Err(err) => {
            eprintln!("无法监听中断信号: {err:?}");
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    // 加载配置并构建自定义运行时以优化线程池配置
    let config = core::config::load_config()?;
    let threads = config
        .server
        .worker_threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;
    runtime.block_on(run(Arc::new(config)))
}
