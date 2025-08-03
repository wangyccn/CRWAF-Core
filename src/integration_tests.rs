//! 端到端集成测试
//!
//! 本模块包含完整的WAF系统集成测试，测试各个组件的协同工作，
//! 包括HTTP服务器、攻击检测、规则引擎、缓存系统等的集成

use serde_json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

use crate::core::config::{AppConfig, CacheConfig, LogConfig, RulesConfig, ServerConfig};
use crate::core::logger::{
    CompressionPolicy, FileLogger, LogConfig as LoggerConfig, RotationPolicy,
};
use crate::core::statistics::Statistics;
use crate::core::sync::DataSyncManager;
use crate::http::server;
use crate::rules::detector::{AttackDetector, DetectionLevel};
use crate::rules::engine::RuleEngine;
use crate::rules::model::{Rule, RuleAction, RuleSeverity, RuleTarget, RuleType};

/// 测试应用配置
fn create_test_config(temp_dir: &TempDir) -> AppConfig {
    AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // 让系统自动分配端口
            grpc_port: None,
        },
        cache: CacheConfig {
            max_size: 1000,
            ttl_seconds: 300,
            enabled: true,
            file_cache: None,
        },
        log: LogConfig {
            level: "info".to_string(),
            file_path: Some(temp_dir.path().join("logs").to_string_lossy().to_string()),
            prefix: Some("test".to_string()),
            rotation_policy: Some("never".to_string()),
            compression: Some(false),
            max_files: Some(10),
        },
        rules: RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec!["test_rules.json".to_string()]),
            custom_regex_file: None,
        },
    }
}

/// 创建测试规则
fn create_test_rules() -> Vec<Rule> {
    let now = chrono::Utc::now();
    vec![
        Rule {
            id: "xss_001".to_string(),
            name: "XSS Script Tag Detection".to_string(),
            description: "Detects basic XSS script tags".to_string(),
            pattern: r"<script[^>]*>.*?</script>".to_string(),
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::High,
            enabled: true,
            created_at: now,
            updated_at: now,
        },
        Rule {
            id: "sql_001".to_string(),
            name: "SQL Injection Detection".to_string(),
            description: "Detects basic SQL injection attempts".to_string(),
            pattern: r"(?i)'.*or.*'.*=.*'".to_string(),
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::High,
            enabled: true,
            created_at: now,
            updated_at: now,
        },
        Rule {
            id: "admin_access".to_string(),
            name: "Admin Path Access".to_string(),
            description: "Detects access to admin paths".to_string(),
            pattern: "/admin".to_string(),
            rule_type: RuleType::Contains,
            target: RuleTarget::Uri,
            action: RuleAction::Log,
            severity: RuleSeverity::Medium,
            enabled: true,
            created_at: now,
            updated_at: now,
        },
    ]
}

/// 初始化测试环境
async fn setup_test_environment(
    temp_dir: &TempDir,
) -> (
    Arc<AppConfig>,
    Arc<AttackDetector>,
    Arc<Statistics>,
    Arc<DataSyncManager>,
    Arc<FileLogger>,
) {
    // 创建配置
    let config = Arc::new(create_test_config(temp_dir));

    // 创建规则文件
    let rules = create_test_rules();
    let rules_file = temp_dir.path().join("test_rules.json");
    let rules_json = serde_json::to_string_pretty(&rules).unwrap();
    std::fs::write(&rules_file, rules_json).unwrap();

    // 初始化规则引擎
    let mut rule_engine = RuleEngine::new().with_config(config.rules.clone());
    rule_engine.load_all_rules().unwrap();

    // 创建攻击检测器
    let detector = Arc::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap());

    // 创建统计和同步管理器
    let statistics = Arc::new(Statistics::new());
    let sync_manager = Arc::new(DataSyncManager::new(
        statistics.clone(),
        "test-instance".to_string(),
    ));

    // 创建日志器
    let log_config = LoggerConfig {
        log_dir: temp_dir.path().join("logs").to_string_lossy().to_string(),
        prefix: "test".to_string(),
        rotation_policy: RotationPolicy::Never,
        compression_policy: CompressionPolicy::None,
        max_files: Some(10),
    };

    std::fs::create_dir_all(&log_config.log_dir).unwrap();
    let logger = Arc::new(FileLogger::new(log_config).unwrap());

    (config, detector, statistics, sync_manager, logger)
}

/// 基础系统集成测试
#[cfg(test)]
mod basic_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_system_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let (config, detector, statistics, sync_manager, logger) =
            setup_test_environment(&temp_dir).await;

        // 验证各组件初始化成功
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.cache.enabled);

        // 验证攻击检测器有规则
        // Note: detector.rule_engine is private, we'll test through public methods instead
        let xss_result = detector.detect_xss("<script>alert('test')</script>");
        assert!(xss_result.detected);

        // 验证统计系统
        let stats = statistics.get_data().await;
        assert_eq!(stats.total_requests, 0);

        // 验证日志器
        logger.access("Test integration log message").unwrap();
    }

    #[tokio::test]
    async fn test_rule_engine_integration() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, _, _, _) = setup_test_environment(&temp_dir).await;

        // 测试XSS检测
        let xss_result = detector.detect_xss("<script>alert('test')</script>");
        assert!(xss_result.detected);
        assert_eq!(xss_result.attack_type, Some("XSS".to_string()));

        // 测试SQL注入检测
        let sql_result = detector.detect_sql_injection("' OR '1'='1");
        assert!(sql_result.detected);
        assert_eq!(sql_result.attack_type, Some("SQL Injection".to_string()));

        // 测试正常内容
        let normal_result = detector.detect_xss("Hello World");
        assert!(!normal_result.detected);
    }

    #[tokio::test]
    async fn test_statistics_integration() {
        let temp_dir = TempDir::new().unwrap();
        let (_, _, statistics, _, _) = setup_test_environment(&temp_dir).await;

        // 记录一些统计信息
        statistics.increment_request();
        statistics.increment_request();
        statistics.increment_defense_hit();

        let stats = statistics.get_data().await;
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.defense_hits, 1);
    }

    #[tokio::test]
    async fn test_logging_integration() {
        let temp_dir = TempDir::new().unwrap();
        let (_, _, _, _, logger) = setup_test_environment(&temp_dir).await;

        // 记录各种类型的日志
        logger.access("Performance test completed").unwrap();
        logger
            .attack("XSS attack detected from 192.168.1.101")
            .unwrap();
        logger.system("System started").unwrap();

        // 等待文件写入
        sleep(Duration::from_millis(100)).await;

        // 验证日志文件存在
        let log_dir = temp_dir.path().join("logs");
        assert!(log_dir.exists());

        let entries = std::fs::read_dir(&log_dir).unwrap();
        let log_files: Vec<_> = entries.collect();
        assert!(log_files.len() > 0);
    }
}

/// HTTP服务器集成测试
#[cfg(test)]
mod http_server_integration_tests {
    use super::*;
    use reqwest;
    use tokio::net::TcpListener;

    async fn start_test_server(
        config: Arc<AppConfig>,
        detector: Arc<AttackDetector>,
        statistics: Arc<Statistics>,
        sync_manager: Arc<DataSyncManager>,
        logger: Arc<FileLogger>,
    ) -> SocketAddr {
        // 绑定到随机端口
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 启动服务器
        tokio::spawn(async move {
            let app = server::create_router(config, sync_manager, statistics, detector, logger);
            axum::serve(listener, app).await.unwrap();
        });

        // 等待服务器启动
        sleep(Duration::from_millis(100)).await;
        addr
    }

    #[tokio::test]
    async fn test_health_check_endpoint() {
        let temp_dir = TempDir::new().unwrap();
        let (config, detector, statistics, sync_manager, logger) =
            setup_test_environment(&temp_dir).await;
        let addr = start_test_server(config, detector, statistics, sync_manager, logger).await;

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let json: serde_json::Value = response.json().await.unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_waf_status_endpoint() {
        let temp_dir = TempDir::new().unwrap();
        let (config, detector, statistics, sync_manager, logger) =
            setup_test_environment(&temp_dir).await;
        let addr = start_test_server(config, detector, statistics, sync_manager, logger).await;

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("http://{}/waf/status", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/html"));
        assert!(response.headers().get("x-protected-by").unwrap() == "CRWAF");

        let html = response.text().await.unwrap();
        assert!(html.contains("CRWAF"));
        assert!(html.contains("运行中"));
    }

    #[tokio::test]
    async fn test_static_javascript_files() {
        let temp_dir = TempDir::new().unwrap();
        let (config, detector, statistics, sync_manager, logger) =
            setup_test_environment(&temp_dir).await;
        let addr = start_test_server(config, detector, statistics, sync_manager, logger).await;

        let client = reqwest::Client::new();

        // 测试 challenge.js
        let response = client
            .get(&format!("http://{}/waf/challenge.js", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("application/javascript"));

        // 测试 click-challenge.js
        let response = client
            .get(&format!("http://{}/waf/click-challenge.js", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("application/javascript"));
    }

    #[tokio::test]
    async fn test_not_implemented_endpoints() {
        let temp_dir = TempDir::new().unwrap();
        let (config, detector, statistics, sync_manager, logger) =
            setup_test_environment(&temp_dir).await;
        let addr = start_test_server(config, detector, statistics, sync_manager, logger).await;

        let client = reqwest::Client::new();

        // 测试验证端点（暂未实现）
        let endpoints = vec!["/waf/verify", "/waf/verify-click", "/waf/verify-captcha"];

        for endpoint in endpoints {
            let response = client
                .post(&format!("http://{}{}", addr, endpoint))
                .send()
                .await
                .unwrap();

            assert_eq!(response.status(), 501);
            assert_eq!(response.text().await.unwrap(), "Not implemented");
        }
    }

    #[tokio::test]
    async fn test_fallback_handler() {
        let temp_dir = TempDir::new().unwrap();
        let (config, detector, statistics, sync_manager, logger) =
            setup_test_environment(&temp_dir).await;
        let addr = start_test_server(config, detector, statistics, sync_manager, logger).await;

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("http://{}/nonexistent-path", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 404);
        assert_eq!(response.text().await.unwrap(), "Not Found");
    }
}

/// 攻击检测集成测试
#[cfg(test)]
mod attack_detection_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_xss_detection_flow() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, statistics, _, logger) = setup_test_environment(&temp_dir).await;

        let malicious_payloads = vec![
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ];

        for payload in malicious_payloads {
            // 检测攻击
            let result = detector.detect_xss(payload);
            assert!(result.detected, "Should detect XSS in: {}", payload);

            // 记录统计
            statistics.increment_defense_hit();

            // 记录攻击日志
            logger
                .attack("XSS attack detected from 192.168.1.100")
                .unwrap();
        }

        let stats = statistics.get_data().await;
        assert_eq!(stats.defense_hits, 3);
    }

    #[tokio::test]
    async fn test_sql_injection_detection_flow() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, statistics, _, logger) = setup_test_environment(&temp_dir).await;

        let malicious_payloads = vec![
            "' OR '1'='1",
            "admin' OR '1'='1'--",
            "'; DROP TABLE users--",
        ];

        for payload in malicious_payloads {
            // 检测攻击
            let result = detector.detect_sql_injection(payload);
            assert!(
                result.detected,
                "Should detect SQL injection in: {}",
                payload
            );

            // 记录统计
            statistics.increment_defense_hit();

            // 记录攻击日志
            logger
                .attack("SQL Injection detected from 192.168.1.101")
                .unwrap();
        }

        let stats = statistics.get_data().await;
        assert_eq!(stats.defense_hits, 3);
    }

    #[tokio::test]
    async fn test_multiple_attack_detection() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, _, _, _) = setup_test_environment(&temp_dir).await;

        // 包含多种攻击类型的载荷
        let complex_payload = "<script>alert('xss')</script>' OR 1=1--";

        let xss_result = detector.detect_xss(complex_payload);
        let sql_result = detector.detect_sql_injection(complex_payload);

        // 应该同时检测到XSS和SQL注入
        assert!(xss_result.detected);
        assert!(sql_result.detected);
    }

    #[tokio::test]
    async fn test_rule_based_detection() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, _, _, _) = setup_test_environment(&temp_dir).await;

        // 测试基于规则的检测（使用公共API）
        let admin_content = "<script>alert('admin')</script>"; // XSS content that should be detected
        let result = detector.detect_xss(admin_content);

        // 应该检测到XSS攻击
        assert!(result.detected);
        assert_eq!(result.attack_type, Some("XSS".to_string()));
    }
}

/// 系统性能集成测试
#[cfg(test)]
mod performance_integration_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_concurrent_attack_detection() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, statistics, _, _) = setup_test_environment(&temp_dir).await;

        let detector = Arc::new(detector);
        let statistics = Arc::new(statistics);
        let mut handles = Vec::new();

        let payloads = vec![
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "normal content",
            "<img onerror=alert(1) src=x>",
            "'; DROP TABLE users--",
        ];

        // 并发检测100次
        for i in 0..100 {
            let detector_clone = detector.clone();
            let statistics_clone = statistics.clone();
            let payload = payloads[i % payloads.len()].to_string();

            let handle = tokio::spawn(async move {
                let xss_result = detector_clone.detect_xss(&payload);
                let sql_result = detector_clone.detect_sql_injection(&payload);

                if xss_result.detected || sql_result.detected {
                    statistics_clone.increment_defense_hit();
                } else {
                    statistics_clone.increment_request();
                }
            });

            handles.push(handle);
        }

        let start = Instant::now();
        for handle in handles {
            handle.await.unwrap();
        }
        let duration = start.elapsed();

        println!("100次并发攻击检测用时: {:?}", duration);
        assert!(duration.as_millis() < 5000, "并发检测性能不达标");

        let stats = statistics.get_data().await;
        assert_eq!(stats.total_requests + stats.defense_hits, 100);
    }

    #[tokio::test]
    async fn test_system_throughput() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, statistics, _, logger) = setup_test_environment(&temp_dir).await;

        let start = Instant::now();

        // 模拟1000个请求的处理
        for i in 0..1000 {
            let payload = if i % 10 == 0 {
                "<script>alert(1)</script>" // 10%的恶意请求
            } else {
                "normal request content"
            };

            let result = detector.detect_xss(payload);

            if result.detected {
                statistics.increment_defense_hit();
                logger
                    .attack("Attack detected during performance test")
                    .unwrap();
            } else {
                statistics.increment_request();
                logger.access("Normal request processed").unwrap();
            }
        }

        let duration = start.elapsed();
        let rps = 1000.0 / duration.as_secs_f64();

        println!("系统吞吐量: {:.2} RPS", rps);
        println!("处理1000个请求用时: {:?}", duration);

        // 验证处理速度合理
        assert!(rps > 100.0, "系统吞吐量不达标: {:.2} RPS", rps);

        let stats = statistics.get_data().await;
        assert_eq!(stats.total_requests + stats.defense_hits, 1000);
        assert_eq!(stats.defense_hits, 100); // 10%恶意请求
    }
}

/// 数据同步集成测试
#[cfg(test)]
mod data_sync_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_statistics_sync() {
        let temp_dir = TempDir::new().unwrap();
        let (_, _, statistics, sync_manager, _) = setup_test_environment(&temp_dir).await;

        // 记录一些统计信息
        for _ in 0..10 {
            statistics.increment_request();
        }
        for _ in 0..5 {
            statistics.increment_defense_hit();
        }

        // 测试同步管理器功能
        let stats_data = sync_manager.get_statistics_data().await.unwrap();
        assert_eq!(stats_data.total_requests, 10);

        let stats = statistics.get_data().await;
        assert_eq!(stats.total_requests, 10);
        assert_eq!(stats.defense_hits, 5);
    }

    #[tokio::test]
    async fn test_sync_manager_instance_id() {
        let temp_dir = TempDir::new().unwrap();
        let (_, _, _, sync_manager, _) = setup_test_environment(&temp_dir).await;

        let instance_id = sync_manager.get_instance_id();
        assert_eq!(instance_id, "test-instance");
    }
}

/// 错误处理集成测试
#[cfg(test)]
mod error_handling_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_invalid_rule_handling() {
        let temp_dir = TempDir::new().unwrap();

        // 创建包含无效规则的规则文件
        let invalid_rules = vec![Rule {
            id: "invalid_regex".to_string(),
            name: "Invalid Regex Rule".to_string(),
            description: "Rule with invalid regex pattern".to_string(),
            pattern: "[invalid regex(".to_string(), // 无效的正则表达式
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::High,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }];

        let rules_file = temp_dir.path().join("invalid_rules.json");
        let rules_json = serde_json::to_string_pretty(&invalid_rules).unwrap();
        std::fs::write(&rules_file, rules_json).unwrap();

        let config = RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec!["invalid_rules.json".to_string()]),
            custom_regex_file: None,
        };

        let mut rule_engine = RuleEngine::new().with_config(config);

        // 加载规则应该成功（无效规则会被跳过）
        assert!(rule_engine.load_all_rules().is_ok());

        // 创建检测器应该成功
        let detector = AttackDetector::new(rule_engine, DetectionLevel::Medium);
        assert!(detector.is_ok());
    }

    #[tokio::test]
    async fn test_logging_error_handling() {
        let temp_dir = TempDir::new().unwrap();

        // 创建一个只读目录来测试日志错误处理
        let readonly_dir = temp_dir.path().join("readonly");
        std::fs::create_dir(&readonly_dir).unwrap();

        // 在某些系统上设置只读权限可能不工作，所以我们测试不存在的父目录
        let nonexistent_dir = temp_dir.path().join("nonexistent").join("logs");

        let log_config = LoggerConfig {
            log_dir: nonexistent_dir.to_string_lossy().to_string(),
            prefix: "test".to_string(),
            rotation_policy: RotationPolicy::Never,
            compression_policy: CompressionPolicy::None,
            max_files: Some(10),
        };

        // 创建日志器应该失败或能处理错误
        let logger_result = FileLogger::new(log_config);

        // 如果创建失败，应该返回错误；如果成功，应该能正常工作
        match logger_result {
            Ok(logger) => {
                // 如果创建成功，尝试写入日志应该不会崩溃
                let _ = logger.system("Test error log").unwrap();
            }
            Err(_) => {
                // 创建失败是预期的，因为目录不存在
            }
        }
    }

    #[tokio::test]
    async fn test_detection_with_large_payload() {
        let temp_dir = TempDir::new().unwrap();
        let (_, detector, _, _, _) = setup_test_environment(&temp_dir).await;

        // 创建一个很大的载荷
        let large_payload = "A".repeat(100_000);
        let malicious_large_payload = format!("{}<script>alert(1)</script>", large_payload);

        // 系统应该能处理大载荷而不崩溃
        let result = detector.detect_xss(&malicious_large_payload);
        assert!(result.detected);

        let normal_result = detector.detect_xss(&large_payload);
        assert!(!normal_result.detected);
    }
}
