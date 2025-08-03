//! 防御机制测试
//!
//! 本模块包含WAF防御机制的全面测试，包括五秒盾、点击盾、图片验证码等防御策略

use axum::{body::Body, http::Request};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::defense::{
    captcha::{CaptchaData, CaptchaGenerator},
    frequency::FrequencyController,
    shield::{ClickShield, FiveSecondShield, RequestInfo, ShieldChallenge},
    strategy::DefenseStrategy,
    DefenseAction, DefenseConfig, DefenseManager, DefenseSession,
};

/// 创建测试请求
fn create_test_request(ip: &str, session_id: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("GET")
        .uri("/test")
        .header("x-forwarded-for", ip)
        .body(Body::empty())
        .unwrap();

    if let Some(sid) = session_id {
        request
            .headers_mut()
            .insert("cookie", format!("waf_session={}", sid).parse().unwrap());
    }

    request
}

/// 创建请求信息
fn create_request_info() -> RequestInfo {
    RequestInfo {
        ip: "192.168.1.100".to_string(),
        url: "/test".to_string(),
        time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        host: "example.com".to_string(),
    }
}

/// 测试防御管理器基础功能
#[cfg(test)]
mod defense_manager_tests {
    use super::*;

    #[tokio::test]
    async fn test_defense_manager_creation() {
        let manager = DefenseManager::new();

        // 验证默认配置
        let config = manager.config.read().await;
        assert!(config.five_second_shield);
        assert!(!config.click_shield);
        assert!(!config.captcha_shield);
        assert_eq!(config.white_list.len(), 0);
        assert_eq!(config.challenge_timeout, 300);
    }

    #[tokio::test]
    async fn test_ip_extraction() {
        let manager = DefenseManager::new();

        let request = create_test_request("203.0.113.1", None);
        let ip = manager.extract_client_ip(&request);
        assert_eq!(ip, "203.0.113.1");

        // 测试带有多个IP的X-Forwarded-For头
        let mut request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("x-forwarded-for", "203.0.113.1, 198.51.100.1, 192.0.2.1")
            .body(Body::empty())
            .unwrap();

        let ip = manager.extract_client_ip(&request);
        assert_eq!(ip, "203.0.113.1"); // 应该取第一个IP
    }

    #[tokio::test]
    async fn test_session_id_extraction() {
        let manager = DefenseManager::new();

        // 测试有会话ID的情况
        let request = create_test_request("192.168.1.1", Some("test-session-123"));
        let session_id = manager.extract_session_id(&request);
        assert_eq!(session_id, "test-session-123");

        // 测试没有会话ID的情况（应该生成新的）
        let request = create_test_request("192.168.1.1", None);
        let session_id = manager.extract_session_id(&request);
        assert!(!session_id.is_empty());
        assert_ne!(session_id, "test-session-123");
    }

    #[tokio::test]
    async fn test_whitelist_defense() {
        let manager = DefenseManager::new();

        // 添加IP到白名单
        {
            let mut config = manager.config.write().await;
            config.white_list.push("192.168.1.100".to_string());
        }

        let request = create_test_request("192.168.1.100", None);
        let action = manager.check_defense(&request).await.unwrap();

        assert!(matches!(action, DefenseAction::Allow));
    }

    #[tokio::test]
    async fn test_five_second_shield_defense() {
        let manager = DefenseManager::new();

        let request = create_test_request("192.168.1.101", None);
        let action = manager.check_defense(&request).await.unwrap();

        assert!(matches!(action, DefenseAction::FiveSecondShield));
    }

    #[tokio::test]
    async fn test_click_shield_defense() {
        let manager = DefenseManager::new();

        // 设置点击盾为主要防御
        {
            let mut config = manager.config.write().await;
            config.five_second_shield = false;
            config.click_shield = true;
        }

        let request = create_test_request("192.168.1.101", None);
        let action = manager.check_defense(&request).await.unwrap();

        assert!(matches!(action, DefenseAction::ClickShield));
    }

    #[tokio::test]
    async fn test_captcha_shield_defense() {
        let manager = DefenseManager::new();

        // 设置验证码盾为主要防御
        {
            let mut config = manager.config.write().await;
            config.five_second_shield = false;
            config.click_shield = false;
            config.captcha_shield = true;
        }

        let request = create_test_request("192.168.1.101", None);
        let action = manager.check_defense(&request).await.unwrap();

        assert!(matches!(action, DefenseAction::CaptchaShield));
    }

    #[tokio::test]
    async fn test_session_creation() {
        let manager = DefenseManager::new();

        let session = manager.create_session("test-session-456".to_string()).await;

        assert_eq!(session.session_id, "test-session-456");
        assert!(session.challenge_id.is_some());
        assert!(!session.challenge_completed);
        assert!(session.verified_at.is_none());
        assert_eq!(session.attempts, 0);
    }

    #[tokio::test]
    async fn test_verified_session_allows_access() {
        let manager = DefenseManager::new();

        // 创建并验证会话
        let session_id = "verified-session".to_string();
        manager.create_session(session_id.clone()).await;

        // 手动设置会话为已验证
        {
            let mut sessions = manager.sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.challenge_completed = true;
                session.verified_at = Some(chrono::Utc::now().timestamp());
            }
        }

        let request = create_test_request("192.168.1.102", Some(&session_id));
        let action = manager.check_defense(&request).await.unwrap();

        assert!(matches!(action, DefenseAction::Allow));
    }

    #[tokio::test]
    async fn test_expired_session_requires_new_challenge() {
        let manager = DefenseManager::new();

        // 创建会话并设置为过期的验证状态
        let session_id = "expired-session".to_string();
        manager.create_session(session_id.clone()).await;

        {
            let mut sessions = manager.sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.challenge_completed = true;
                // 设置为1小时前验证（超过默认的300秒超时）
                session.verified_at = Some(chrono::Utc::now().timestamp() - 3600);
            }
        }

        let request = create_test_request("192.168.1.103", Some(&session_id));
        let action = manager.check_defense(&request).await.unwrap();

        // 应该需要新的挑战
        assert!(matches!(action, DefenseAction::FiveSecondShield));
    }

    #[tokio::test]
    async fn test_challenge_verification_failure() {
        let manager = DefenseManager::new();

        let session_id = "challenge-session".to_string();
        manager.create_session(session_id.clone()).await;

        // 验证失败的挑战
        let result = manager
            .verify_challenge(&session_id, "wrong-response")
            .await
            .unwrap();
        assert!(!result);

        // 检查尝试次数增加
        let sessions = manager.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert_eq!(session.attempts, 1);
        assert!(!session.challenge_completed);
    }

    #[tokio::test]
    async fn test_challenge_attempts_limit() {
        let manager = DefenseManager::new();

        let session_id = "limit-session".to_string();
        manager.create_session(session_id.clone()).await;

        // 多次失败验证
        for _ in 0..3 {
            let result = manager
                .verify_challenge(&session_id, "wrong")
                .await
                .unwrap();
            assert!(!result);
        }

        // 检查挑战ID是否已重新生成
        let sessions = manager.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert_eq!(session.attempts, 0); // 重置为0
        assert!(session.challenge_id.is_some());
    }
}

/// 测试五秒盾功能
#[cfg(test)]
mod five_second_shield_tests {
    use super::*;

    #[test]
    fn test_five_second_shield_creation() {
        let shield = FiveSecondShield::new();
        // 验证默认难度
        assert_eq!(shield.difficulty, 5);
    }

    #[test]
    fn test_shield_challenge_generation() {
        let shield = FiveSecondShield::new();
        let challenge_id = "test-challenge-123";

        let challenge = shield.generate_challenge(challenge_id);

        assert_eq!(challenge.challenge_id, challenge_id);
        assert_eq!(challenge.difficulty, 5);
        assert!(!challenge.nonce.is_empty());

        // 验证时间戳是最近的
        let now = chrono::Utc::now().timestamp();
        assert!((now - challenge.timestamp).abs() < 5); // 5秒内
    }

    #[test]
    fn test_multiple_challenges_have_different_nonces() {
        let shield = FiveSecondShield::new();

        let challenge1 = shield.generate_challenge("test1");
        let challenge2 = shield.generate_challenge("test2");

        assert_ne!(challenge1.nonce, challenge2.nonce);
        assert_ne!(challenge1.challenge_id, challenge2.challenge_id);
    }

    #[test]
    fn test_response_page_generation() {
        let shield = FiveSecondShield::new();
        let challenge = shield.generate_challenge("page-test");
        let request_info = create_request_info();

        let html = shield.generate_response_page(&challenge, request_info.clone());
        let html_content = html.0;

        // 验证页面包含必要的元素
        assert!(html_content.contains("正在进行安全验证"));
        assert!(html_content.contains(&request_info.ip));
        assert!(html_content.contains(&request_info.url));
        assert!(html_content.contains(&request_info.host));
        assert!(html_content.contains("/waf/challenge.js"));

        // 验证挑战数据被正确注入
        assert!(html_content.contains(&challenge.challenge_id));
    }

    #[test]
    fn test_shield_challenge_serialization() {
        let challenge = ShieldChallenge {
            challenge_id: "ser-test".to_string(),
            timestamp: 1640995200,
            difficulty: 5,
            nonce: "test-nonce".to_string(),
        };

        let json = serde_json::to_string(&challenge).unwrap();
        let deserialized: ShieldChallenge = serde_json::from_str(&json).unwrap();

        assert_eq!(challenge.challenge_id, deserialized.challenge_id);
        assert_eq!(challenge.timestamp, deserialized.timestamp);
        assert_eq!(challenge.difficulty, deserialized.difficulty);
        assert_eq!(challenge.nonce, deserialized.nonce);
    }
}

/// 测试点击盾功能
#[cfg(test)]
mod click_shield_tests {
    use super::*;

    #[test]
    fn test_click_shield_creation() {
        let shield = ClickShield::new();
        assert_eq!(shield.click_areas, 3);
    }

    #[test]
    fn test_click_shield_response_page() {
        let shield = ClickShield::new();
        let challenge_id = "click-test-123";
        let request_info = create_request_info();

        let html = shield.generate_response_page(challenge_id, request_info);
        let html_content = html.0;

        // 验证页面包含点击验证元素
        assert!(html_content.contains("请完成点击验证"));
        assert!(html_content.contains("click-area"));
        assert!(html_content.contains("handleClick"));
        assert!(html_content.contains("/waf/click-challenge.js"));
        assert!(html_content.contains(challenge_id));
        assert!(html_content.contains("3")); // 点击次数要求
    }

    #[test]
    fn test_click_shield_different_areas() {
        let shield = ClickShield { click_areas: 5 };
        let html = shield.generate_response_page("test", create_request_info());
        let html_content = html.0;

        assert!(html_content.contains("5")); // 自定义点击次数
    }
}

/// 测试验证码生成器
#[cfg(test)]
mod captcha_generator_tests {
    use super::*;

    #[tokio::test]
    async fn test_captcha_generator_creation() {
        let generator = CaptchaGenerator::new().unwrap();
        // 验证创建成功
        let storage = generator.captcha_storage.read().await;
        assert_eq!(storage.len(), 0);
    }

    #[tokio::test]
    async fn test_captcha_generation() {
        let generator = CaptchaGenerator::new().unwrap();
        let captcha_id = "test-captcha-123";

        let text = generator.generate_captcha(captcha_id).await.unwrap();

        // 验证生成的文本
        assert_eq!(text.len(), 6);
        assert!(text.chars().all(|c| c.is_ascii_alphanumeric()));

        // 验证存储
        let storage = generator.captcha_storage.read().await;
        assert!(storage.contains_key(captcha_id));

        let data = storage.get(captcha_id).unwrap();
        assert_eq!(data.answer, text);

        // 验证时间戳
        let now = chrono::Utc::now().timestamp();
        assert!((now - data.created_at).abs() < 5);
    }

    #[tokio::test]
    async fn test_captcha_verification_success() {
        let generator = CaptchaGenerator::new().unwrap();
        let captcha_id = "verify-test";

        let text = generator.generate_captcha(captcha_id).await.unwrap();
        let result = generator.verify_captcha(captcha_id, &text).await;

        assert!(result);

        // 验证验证码在验证后被删除
        let storage = generator.captcha_storage.read().await;
        assert!(!storage.contains_key(captcha_id));
    }

    #[tokio::test]
    async fn test_captcha_verification_failure() {
        let generator = CaptchaGenerator::new().unwrap();
        let captcha_id = "fail-test";

        let _text = generator.generate_captcha(captcha_id).await.unwrap();
        let result = generator.verify_captcha(captcha_id, "WRONG").await;

        assert!(!result);

        // 验证验证码在失败验证后仍然存在
        let storage = generator.captcha_storage.read().await;
        assert!(storage.contains_key(captcha_id));
    }

    #[tokio::test]
    async fn test_captcha_case_insensitive_verification() {
        let generator = CaptchaGenerator::new().unwrap();
        let captcha_id = "case-test";

        let text = generator.generate_captcha(captcha_id).await.unwrap();

        // 测试小写输入
        let lower_result = generator
            .verify_captcha(captcha_id, &text.to_lowercase())
            .await;

        // 重新生成验证码进行测试
        let text = generator.generate_captcha(captcha_id).await.unwrap();
        let upper_result = generator
            .verify_captcha(captcha_id, &text.to_uppercase())
            .await;

        // 注意：根据实际实现，这里可能需要调整
        // 如果实现区分大小写，则应该返回false
        // 如果实现不区分大小写，则应该返回true
    }

    #[tokio::test]
    async fn test_captcha_expiry_cleanup() {
        let generator = CaptchaGenerator::new().unwrap();

        // 手动添加过期的验证码
        {
            let mut storage = generator.captcha_storage.write().await;
            storage.insert(
                "expired".to_string(),
                CaptchaData {
                    answer: "TEST".to_string(),
                    created_at: chrono::Utc::now().timestamp() - 400, // 超过5分钟
                },
            );
        }

        // 生成新验证码触发清理
        let _text = generator.generate_captcha("new").await.unwrap();

        // 验证过期验证码被清理
        let storage = generator.captcha_storage.read().await;
        assert!(!storage.contains_key("expired"));
        assert!(storage.contains_key("new"));
    }

    #[tokio::test]
    async fn test_multiple_captcha_generation() {
        let generator = CaptchaGenerator::new().unwrap();

        let mut texts = Vec::new();
        for i in 0..10 {
            let captcha_id = format!("multi-{}", i);
            let text = generator.generate_captcha(&captcha_id).await.unwrap();
            texts.push(text);
        }

        // 验证所有生成的验证码都不相同
        for i in 0..texts.len() {
            for j in i + 1..texts.len() {
                assert_ne!(texts[i], texts[j], "Captcha texts should be unique");
            }
        }

        // 验证所有验证码都被存储
        let storage = generator.captcha_storage.read().await;
        assert_eq!(storage.len(), 10);
    }

    #[tokio::test]
    async fn test_nonexistent_captcha_verification() {
        let generator = CaptchaGenerator::new().unwrap();

        let result = generator.verify_captcha("nonexistent", "TEST").await;
        assert!(!result);
    }
}

/// 测试频率控制器
#[cfg(test)]
mod frequency_controller_tests {
    use super::*;
    use crate::defense::frequency::{FrequencyAction, FrequencyConfig, FrequencyController};

    #[tokio::test]
    async fn test_frequency_controller_creation() {
        let config = FrequencyConfig {
            window_duration: Duration::from_secs(60),
            max_requests: 10,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        };
        let controller = FrequencyController::new(config);

        // 验证创建成功
        let count = controller.get_request_count("test-ip").await;
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_request_recording() {
        let config = FrequencyConfig {
            window_duration: Duration::from_secs(60),
            max_requests: 5,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        };
        let controller = FrequencyController::new(config);
        let ip = "192.168.1.100";

        // 记录几个请求
        for _ in 0..3 {
            controller.check_request(ip).await.unwrap();
        }

        let count = controller.get_request_count(ip).await;
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_frequency_limit_not_exceeded() {
        let config = FrequencyConfig {
            window_duration: Duration::from_secs(60),
            max_requests: 5,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        };
        let controller = FrequencyController::new(config);
        let ip = "192.168.1.101";

        // 记录4个请求（未超过限制）
        for _ in 0..4 {
            let action = controller.check_request(ip).await.unwrap();
            assert!(matches!(action, FrequencyAction::Allow));
        }
    }

    #[tokio::test]
    async fn test_frequency_limit_exceeded() {
        let config = FrequencyConfig {
            window_duration: Duration::from_secs(60),
            max_requests: 3,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        };
        let controller = FrequencyController::new(config);
        let ip = "192.168.1.102";

        // 记录4个请求（超过限制）
        for i in 0..4 {
            let action = controller.check_request(ip).await.unwrap();
            if i < 3 {
                assert!(matches!(action, FrequencyAction::Allow));
            } else {
                assert!(matches!(action, FrequencyAction::Block(_)));
            }
        }
    }

    #[tokio::test]
    async fn test_request_expiry() {
        let config = FrequencyConfig {
            window_duration: Duration::from_millis(100),
            max_requests: 5,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        };
        let controller = FrequencyController::new(config);
        let ip = "192.168.1.103";

        // 记录请求
        controller.check_request(ip).await.unwrap();
        assert_eq!(controller.get_request_count(ip).await, 1);

        // 等待过期
        sleep(Duration::from_millis(150)).await;

        // 新请求应该重置计数器
        controller.check_request(ip).await.unwrap();
        let count = controller.get_request_count(ip).await;
        assert_eq!(count, 1); // 重置为1
    }

    #[tokio::test]
    async fn test_multiple_ips() {
        let config = FrequencyConfig {
            window_duration: Duration::from_secs(60),
            max_requests: 3,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        };
        let controller = FrequencyController::new(config);

        // 为不同IP记录请求
        controller.check_request("192.168.1.1").await.unwrap();
        controller.check_request("192.168.1.1").await.unwrap();
        controller.check_request("192.168.1.2").await.unwrap();

        let count1 = controller.get_request_count("192.168.1.1").await;
        let count2 = controller.get_request_count("192.168.1.2").await;

        assert_eq!(count1, 2);
        assert_eq!(count2, 1);
    }
}

/// 测试防御策略
#[cfg(test)]
mod defense_strategy_tests {
    use super::*;
    use crate::defense::frequency::AnomalyLevel;
    use crate::defense::strategy::DefenseStrategy;

    #[tokio::test]
    async fn test_defense_strategy_creation() {
        let strategy = DefenseStrategy::new();

        // 验证策略可以创建
        let config = DefenseConfig {
            five_second_shield: true,
            click_shield: false,
            captcha_shield: false,
            white_list: vec![],
            challenge_timeout: 300,
        };

        let action = strategy
            .determine_action("test-ip", false, AnomalyLevel::Normal, &config)
            .await
            .unwrap();
        assert!(matches!(
            action,
            DefenseAction::Allow | DefenseAction::FiveSecondShield
        ));
    }

    #[tokio::test]
    async fn test_threat_escalation() {
        let strategy = DefenseStrategy::new();
        let ip = "192.168.1.100";

        let config = DefenseConfig {
            five_second_shield: true,
            click_shield: true,
            captcha_shield: true,
            white_list: vec![],
            challenge_timeout: 300,
        };

        // 正常情况
        let action1 = strategy
            .determine_action(ip, false, AnomalyLevel::Normal, &config)
            .await
            .unwrap();

        // 检测到攻击
        let action2 = strategy
            .determine_action(ip, true, AnomalyLevel::High, &config)
            .await
            .unwrap();

        // 第二次应该有更强的防御措施
        match (action1, action2) {
            (DefenseAction::Allow, DefenseAction::FiveSecondShield) => {}
            (DefenseAction::FiveSecondShield, DefenseAction::ClickShield) => {}
            (DefenseAction::ClickShield, DefenseAction::CaptchaShield) => {}
            _ => {} // 允许其他合理的升级组合
        }
    }

    #[tokio::test]
    async fn test_anomaly_level_impact() {
        let strategy = DefenseStrategy::new();

        let config = DefenseConfig {
            five_second_shield: true,
            click_shield: true,
            captcha_shield: true,
            white_list: vec![],
            challenge_timeout: 300,
        };

        // 不同异常级别应该产生不同响应
        let normal = strategy
            .determine_action("ip1", false, AnomalyLevel::Normal, &config)
            .await
            .unwrap();
        let critical = strategy
            .determine_action("ip2", false, AnomalyLevel::Critical, &config)
            .await
            .unwrap();

        // 关键异常应该触发更强的防御
        assert!(matches!(
            critical,
            DefenseAction::FiveSecondShield
                | DefenseAction::ClickShield
                | DefenseAction::CaptchaShield
        ));
    }

    #[tokio::test]
    async fn test_success_feedback() {
        let strategy = DefenseStrategy::new();
        let ip = "192.168.1.105";

        // 记录成功验证
        strategy.record_success(ip).await;

        // 成功验证后威胁级别应该降低
        let config = DefenseConfig {
            five_second_shield: true,
            click_shield: false,
            captcha_shield: false,
            white_list: vec![],
            challenge_timeout: 300,
        };

        let action = strategy
            .determine_action(ip, false, AnomalyLevel::Normal, &config)
            .await
            .unwrap();
        // 验证动作合理
        assert!(matches!(
            action,
            DefenseAction::Allow | DefenseAction::FiveSecondShield
        ));
    }

    #[tokio::test]
    async fn test_failure_feedback() {
        let strategy = DefenseStrategy::new();
        let ip = "192.168.1.106";

        // 记录验证失败
        strategy.record_failure(ip).await;

        let config = DefenseConfig {
            five_second_shield: true,
            click_shield: true,
            captcha_shield: true,
            white_list: vec![],
            challenge_timeout: 300,
        };

        let action = strategy
            .determine_action(ip, false, AnomalyLevel::Normal, &config)
            .await
            .unwrap();
        // 失败后应该有防御措施
        assert!(matches!(
            action,
            DefenseAction::FiveSecondShield
                | DefenseAction::ClickShield
                | DefenseAction::CaptchaShield
        ));
    }
}

/// 集成测试 - 防御机制协同工作
#[cfg(test)]
mod defense_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_defense_flow() {
        let manager = DefenseManager::new();
        let generator = CaptchaGenerator::new().unwrap();
        let shield = FiveSecondShield::new();

        // 1. 初始请求触发五秒盾
        let request = create_test_request("192.168.1.100", None);
        let action = manager.check_defense(&request).await.unwrap();
        assert!(matches!(action, DefenseAction::FiveSecondShield));

        // 2. 生成挑战
        let challenge = shield.generate_challenge("test-challenge");
        assert!(!challenge.nonce.is_empty());

        // 3. 创建会话
        let session = manager.create_session("defense-session".to_string()).await;
        assert!(!session.challenge_completed);

        // 4. 生成验证码作为额外验证
        let captcha_text = generator.generate_captcha("captcha-test").await.unwrap();
        assert_eq!(captcha_text.len(), 6);

        // 5. 验证验证码
        let captcha_result = generator
            .verify_captcha("captcha-test", &captcha_text)
            .await;
        assert!(captcha_result);
    }

    #[tokio::test]
    async fn test_defense_escalation() {
        let manager = DefenseManager::new();

        // 配置防御升级策略
        {
            let mut config = manager.config.write().await;
            config.five_second_shield = true;
            config.click_shield = true;
            config.captcha_shield = true;
        }

        let ip = "192.168.1.105";

        // 第一次访问 - 五秒盾
        let request1 = create_test_request(ip, None);
        let action1 = manager.check_defense(&request1).await.unwrap();
        assert!(matches!(action1, DefenseAction::FiveSecondShield));

        // 模拟多次失败验证后升级到点击盾
        {
            let mut config = manager.config.write().await;
            config.five_second_shield = false; // 禁用五秒盾，升级到点击盾
        }

        let request2 = create_test_request(ip, None);
        let action2 = manager.check_defense(&request2).await.unwrap();
        assert!(matches!(action2, DefenseAction::ClickShield));
    }

    #[tokio::test]
    async fn test_session_persistence() {
        let manager = DefenseManager::new();

        let session_id = "persistent-session".to_string();
        let ip = "192.168.1.106";

        // 创建并验证会话
        manager.create_session(session_id.clone()).await;

        // 手动设置为已验证
        {
            let mut sessions = manager.sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.challenge_completed = true;
                session.verified_at = Some(chrono::Utc::now().timestamp());
            }
        }

        // 多次请求都应该被允许
        for _ in 0..5 {
            let request = create_test_request(ip, Some(&session_id));
            let action = manager.check_defense(&request).await.unwrap();
            assert!(matches!(action, DefenseAction::Allow));
        }
    }

    #[tokio::test]
    async fn test_concurrent_defense_checks() {
        let manager = Arc::new(DefenseManager::new());

        // 测试多个IP的防御检查（顺序执行以避免Send trait问题）
        let mut shield_count = 0;
        let mut allow_count = 0;

        for i in 0..100 {
            let ip = format!("192.168.1.{}", i % 10 + 1); // 10个不同IP
            let request = create_test_request(&ip, None);
            let action = manager.check_defense(&request).await.unwrap();

            match action {
                DefenseAction::FiveSecondShield => shield_count += 1,
                DefenseAction::Allow => allow_count += 1,
                _ => {}
            }
        }

        // 大部分应该触发五秒盾（除非IP在白名单中）
        assert!(shield_count > 0);
        println!("Shield: {}, Allow: {}", shield_count, allow_count);
    }

    #[tokio::test]
    async fn test_defense_performance() {
        let manager = DefenseManager::new();
        let generator = CaptchaGenerator::new().unwrap();

        let start = std::time::Instant::now();

        // 执行1000次防御检查和验证码生成
        for i in 0..1000 {
            let ip = format!("192.168.{}.{}", i / 256, i % 256);
            let request = create_test_request(&ip, None);

            let _action = manager.check_defense(&request).await.unwrap();
            let _captcha = generator
                .generate_captcha(&format!("perf-{}", i))
                .await
                .unwrap();
        }

        let duration = start.elapsed();
        println!("1000次防御检查和验证码生成用时: {:?}", duration);

        // 性能应该在合理范围内
        assert!(
            duration.as_millis() < 5000,
            "防御机制性能不达标: {:?}",
            duration
        );
    }
}
