//! 验证码生成和验证的单元测试
//!
//! 本模块包含验证码服务的全面单元测试，测试验证码生成、验证、过期清理等功能

use std::time::{Duration, SystemTime};
use tokio::time::sleep;

use super::captcha::{CaptchaChallenge, CaptchaService};

/// 测试验证码服务基础功能
#[cfg(test)]
mod captcha_service_basic_tests {
    use super::*;

    #[tokio::test]
    async fn test_captcha_service_creation() {
        // 测试默认创建
        let service = CaptchaService::default();
        assert_eq!(service.get_challenge_count().await, 0);

        // 测试自定义TTL创建
        let service = CaptchaService::new(600); // 10分钟
        assert_eq!(service.get_challenge_count().await, 0);
    }

    #[tokio::test]
    async fn test_generate_captcha() {
        let service = CaptchaService::new(300); // 5分钟TTL

        let (challenge_id, image_data) = service.generate_captcha().await.unwrap();

        // 验证返回值格式
        assert!(!challenge_id.is_empty());
        assert!(image_data.starts_with("data:image/png;base64,"));

        // 验证挑战已存储
        assert_eq!(service.get_challenge_count().await, 1);
    }

    #[tokio::test]
    async fn test_multiple_captcha_generation() {
        let service = CaptchaService::new(300);

        // 生成多个验证码
        let mut challenge_ids = Vec::new();
        for _ in 0..5 {
            let (challenge_id, _) = service.generate_captcha().await.unwrap();
            challenge_ids.push(challenge_id);
        }

        // 验证都生成成功且ID不重复
        assert_eq!(challenge_ids.len(), 5);
        assert_eq!(service.get_challenge_count().await, 5);

        // 验证ID唯一性
        for i in 0..challenge_ids.len() {
            for j in i + 1..challenge_ids.len() {
                assert_ne!(challenge_ids[i], challenge_ids[j]);
            }
        }
    }

    #[tokio::test]
    async fn test_captcha_verification_success() {
        let service = CaptchaService::new(300);

        // 生成验证码
        let (challenge_id, _) = service.generate_captcha().await.unwrap();

        // 获取正确的验证码（用于测试）
        let correct_code = service.get_challenge_code(&challenge_id).await.unwrap();

        // 测试正确验证
        let result = service
            .verify_captcha(&challenge_id, &correct_code)
            .await
            .unwrap();
        assert!(result);

        // 验证成功后挑战应被移除
        assert_eq!(service.get_challenge_count().await, 0);
    }

    #[tokio::test]
    async fn test_captcha_verification_failure() {
        let service = CaptchaService::new(300);

        // 生成验证码
        let (challenge_id, _) = service.generate_captcha().await.unwrap();

        // 测试错误验证
        let result = service
            .verify_captcha(&challenge_id, "WRONG")
            .await
            .unwrap();
        assert!(!result);

        // 验证失败后挑战应仍然存在
        assert_eq!(service.get_challenge_count().await, 1);
    }

    #[tokio::test]
    async fn test_captcha_case_insensitive_verification() {
        let service = CaptchaService::new(300);

        // 生成验证码
        let (challenge_id, _) = service.generate_captcha().await.unwrap();

        // 获取正确答案
        let correct_code = service.get_challenge_code(&challenge_id).await.unwrap();

        // 测试小写输入
        let result = service
            .verify_captcha(&challenge_id, &correct_code.to_lowercase())
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_nonexistent_challenge_verification() {
        let service = CaptchaService::new(300);

        // 测试不存在的挑战ID
        let result = service
            .verify_captcha("nonexistent_id", "ABCD")
            .await
            .unwrap();
        assert!(!result);
    }
}

/// 测试验证码过期和清理功能
#[cfg(test)]
mod captcha_expiry_tests {
    use super::*;

    #[tokio::test]
    async fn test_captcha_expiry() {
        let service = CaptchaService::new(1); // 1秒TTL

        // 生成验证码
        let (challenge_id, _) = service.generate_captcha().await.unwrap();

        // 等待过期
        sleep(Duration::from_secs(2)).await;

        // 获取正确答案（即使过期也要测试）
        let correct_code = service
            .get_challenge_code(&challenge_id)
            .await
            .unwrap_or_else(|| "ABCD".to_string()); // 如果已被清理，使用默认值

        // 验证过期的验证码
        let result = service
            .verify_captcha(&challenge_id, &correct_code)
            .await
            .unwrap();
        assert!(!result);

        // 过期的挑战应该被自动移除
        assert_eq!(service.get_challenge_count().await, 0);
    }

    #[tokio::test]
    async fn test_cleanup_expired_challenges() {
        let service = CaptchaService::new(1); // 1秒TTL

        // 生成多个验证码
        for _ in 0..3 {
            service.generate_captcha().await.unwrap();
        }
        assert_eq!(service.get_challenge_count().await, 3);

        // 等待过期
        sleep(Duration::from_secs(2)).await;

        // 执行清理
        service.cleanup_expired().await.unwrap();

        // 所有过期的挑战应该被清理
        assert_eq!(service.get_challenge_count().await, 0);
    }

    #[tokio::test]
    async fn test_partial_cleanup_expired_challenges() {
        let service = CaptchaService::new(2); // 2秒TTL

        // 生成第一批验证码
        for _ in 0..2 {
            service.generate_captcha().await.unwrap();
        }

        // 等待1秒
        sleep(Duration::from_secs(1)).await;

        // 生成第二批验证码
        for _ in 0..2 {
            service.generate_captcha().await.unwrap();
        }
        assert_eq!(service.get_challenge_count().await, 4);

        // 再等待1秒，确保第一批过期而第二批仍在有效期内
        sleep(Duration::from_secs(1)).await;

        // 执行清理
        service.cleanup_expired().await.unwrap();

        // 只有第二批验证码应该保留
        assert_eq!(service.get_challenge_count().await, 2);
    }

    #[tokio::test]
    async fn test_verify_and_cleanup_interaction() {
        let service = CaptchaService::new(300); // 5分钟TTL

        // 生成验证码
        let (challenge_id, _) = service.generate_captcha().await.unwrap();

        // 执行清理（不应该影响有效的验证码）
        service.cleanup_expired().await.unwrap();
        assert_eq!(service.get_challenge_count().await, 1);

        // 获取正确答案并验证
        let correct_code = service.get_challenge_code(&challenge_id).await.unwrap();

        let result = service
            .verify_captcha(&challenge_id, &correct_code)
            .await
            .unwrap();
        assert!(result);

        // 验证成功后应该被移除
        assert_eq!(service.get_challenge_count().await, 0);
    }
}

/// 测试验证码挑战结构
#[cfg(test)]
mod captcha_challenge_tests {
    use super::*;

    #[test]
    fn test_captcha_challenge_creation() {
        let now = SystemTime::now();
        let ttl = Duration::from_secs(300);

        let challenge = CaptchaChallenge {
            code: "ABCD".to_string(),
            image_data: "data:image/png;base64,test".to_string(),
            created_at: now,
            ttl,
        };

        assert_eq!(challenge.code, "ABCD");
        assert!(challenge.image_data.starts_with("data:image/png;base64,"));
        assert_eq!(challenge.ttl, ttl);
    }

    #[test]
    fn test_captcha_challenge_expiry_check() {
        let past_time = SystemTime::now() - Duration::from_secs(400);
        let ttl = Duration::from_secs(300);

        let challenge = CaptchaChallenge {
            code: "ABCD".to_string(),
            image_data: "data:image/png;base64,test".to_string(),
            created_at: past_time,
            ttl,
        };

        let now = SystemTime::now();
        let elapsed = now.duration_since(challenge.created_at).unwrap();
        assert!(elapsed > challenge.ttl);
    }
}

/// 测试并发场景
#[cfg(test)]
mod captcha_concurrency_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::task;

    #[tokio::test]
    async fn test_concurrent_captcha_generation() {
        let service = Arc::new(CaptchaService::new(300));
        let mut handles = Vec::new();

        // 并发生成10个验证码
        for _ in 0..10 {
            let service_clone = service.clone();
            let handle = task::spawn(async move { service_clone.generate_captcha().await });
            handles.push(handle);
        }

        // 等待所有任务完成
        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            results.push(result);
        }

        // 验证所有验证码都生成成功
        assert_eq!(results.len(), 10);
        assert_eq!(service.get_challenge_count().await, 10);

        // 验证所有ID都不重复
        let mut challenge_ids: Vec<String> = results.into_iter().map(|(id, _)| id).collect();
        challenge_ids.sort();
        challenge_ids.dedup();
        assert_eq!(challenge_ids.len(), 10);
    }

    #[tokio::test]
    async fn test_concurrent_verification() {
        let service = Arc::new(CaptchaService::new(300));

        // 生成验证码
        let (challenge_id, _) = service.generate_captcha().await.unwrap();

        // 获取正确答案
        let correct_code = service.get_challenge_code(&challenge_id).await.unwrap();

        let mut handles = Vec::new();

        // 并发验证（一个正确，其他错误）
        let service_clone = service.clone();
        let challenge_id_clone = challenge_id.clone();
        let correct_code_clone = correct_code.clone();
        handles.push(task::spawn(async move {
            service_clone
                .verify_captcha(&challenge_id_clone, &correct_code_clone)
                .await
        }));

        // 添加一些错误验证
        for i in 0..5 {
            let service_clone = service.clone();
            let challenge_id_clone = challenge_id.clone();
            handles.push(task::spawn(async move {
                service_clone
                    .verify_captcha(&challenge_id_clone, &format!("WRONG{}", i))
                    .await
            }));
        }

        // 等待所有任务完成
        let mut success_count = 0;
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            if result {
                success_count += 1;
            }
        }

        // 只有一个应该成功
        assert_eq!(success_count, 1);
        // 成功验证后挑战应该被移除
        assert_eq!(service.get_challenge_count().await, 0);
    }

    #[tokio::test]
    async fn test_concurrent_cleanup() {
        let service = Arc::new(CaptchaService::new(1)); // 1秒TTL

        // 生成验证码
        for _ in 0..5 {
            service.generate_captcha().await.unwrap();
        }
        assert_eq!(service.get_challenge_count().await, 5);

        // 等待过期
        sleep(Duration::from_secs(2)).await;

        let mut handles = Vec::new();

        // 并发清理
        for _ in 0..3 {
            let service_clone = service.clone();
            let handle = task::spawn(async move { service_clone.cleanup_expired().await });
            handles.push(handle);
        }

        // 等待所有清理任务完成
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // 所有过期的挑战都应该被清理
        assert_eq!(service.get_challenge_count().await, 0);
    }
}

/// 性能测试
#[cfg(test)]
mod captcha_performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_captcha_generation_performance() {
        let service = CaptchaService::new(300);

        let start = Instant::now();

        // 生成100个验证码
        for _ in 0..100 {
            service.generate_captcha().await.unwrap();
        }

        let duration = start.elapsed();
        println!("生成100个验证码用时: {:?}", duration);

        // 验证生成速度合理（应该在几秒内完成）
        assert!(
            duration.as_secs() < 10,
            "验证码生成速度太慢: {:?}",
            duration
        );
        assert_eq!(service.get_challenge_count().await, 100);
    }

    #[tokio::test]
    async fn test_verification_performance() {
        let service = CaptchaService::new(300);

        // 生成多个验证码
        let mut challenges = Vec::new();
        for _ in 0..50 {
            let (challenge_id, _) = service.generate_captcha().await.unwrap();
            challenges.push(challenge_id);
        }

        let start = Instant::now();

        // 批量验证（使用错误答案）
        for challenge_id in &challenges {
            service.verify_captcha(challenge_id, "WRONG").await.unwrap();
        }

        let duration = start.elapsed();
        println!("验证50个验证码用时: {:?}", duration);

        // 验证速度应该很快
        assert!(duration.as_millis() < 1000, "验证速度太慢: {:?}", duration);
    }

    #[tokio::test]
    async fn test_cleanup_performance() {
        let service = CaptchaService::new(1); // 1秒TTL

        // 生成大量验证码
        for _ in 0..1000 {
            service.generate_captcha().await.unwrap();
        }
        assert_eq!(service.get_challenge_count().await, 1000);

        // 等待过期
        sleep(Duration::from_secs(2)).await;

        let start = Instant::now();
        service.cleanup_expired().await.unwrap();
        let duration = start.elapsed();

        println!("清理1000个过期验证码用时: {:?}", duration);

        // 清理应该很快
        assert!(duration.as_millis() < 500, "清理速度太慢: {:?}", duration);
        assert_eq!(service.get_challenge_count().await, 0);
    }
}
