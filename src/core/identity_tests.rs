//! 身份识别与会话管理的单元测试
//!
//! 本模块包含身份识别服务的全面单元测试，测试会话管理、请求记录、指纹生成等功能

use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

use super::identity::{
    BrowserFingerprint, DeviceFingerprint, IdentityService, IdentityStats, RequestInfo,
    SessionInfo, ValidationLevel,
};

/// 测试身份识别服务基础功能
#[cfg(test)]
mod identity_service_basic_tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_service_creation() {
        // 测试默认创建
        let service = IdentityService::default();
        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.total_requests, 0);

        // 测试自定义参数创建
        let service = IdentityService::new(48, 120); // 48小时会话，120分钟请求
        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 0);
    }

    #[tokio::test]
    async fn test_session_id_generation() {
        let session_id1 = IdentityService::generate_session_id();
        let session_id2 = IdentityService::generate_session_id();

        // 验证ID格式
        assert!(session_id1.starts_with("WAF_"));
        assert!(session_id2.starts_with("WAF_"));

        // 验证ID唯一性
        assert_ne!(session_id1, session_id2);

        // 验证ID包含时间戳和UUID
        let parts1: Vec<&str> = session_id1.split('_').collect();
        assert_eq!(parts1.len(), 3);
        assert_eq!(parts1[0], "WAF");
        assert!(parts1[1].parse::<u128>().is_ok()); // 时间戳
        assert_eq!(parts1[2].len(), 32); // UUID简单格式
    }

    #[tokio::test]
    async fn test_request_id_generation() {
        let request_id1 = IdentityService::generate_request_id();
        let request_id2 = IdentityService::generate_request_id();

        // 验证ID格式
        assert!(request_id1.starts_with("REQ_"));
        assert!(request_id2.starts_with("REQ_"));

        // 验证ID唯一性
        assert_ne!(request_id1, request_id2);

        // 验证ID包含纳秒时间戳和UUID
        let parts1: Vec<&str> = request_id1.split('_').collect();
        assert_eq!(parts1.len(), 3);
        assert_eq!(parts1[0], "REQ");
        assert!(parts1[1].parse::<u128>().is_ok()); // 纳秒时间戳
        assert_eq!(parts1[2].len(), 32); // UUID简单格式
    }

    #[tokio::test]
    async fn test_create_session() {
        let service = IdentityService::default();

        let session_id = service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;

        assert!(session_id.starts_with("WAF_"));

        let session = service.get_session(&session_id).await.unwrap();
        assert_eq!(session.user_ip, "192.168.1.100");
        assert_eq!(session.user_agent, "Mozilla/5.0");
        assert_eq!(session.device_fingerprint, "device_fp_1");
        assert_eq!(session.browser_fingerprint, "browser_fp_1");
        assert_eq!(session.access_count, 1);
        assert!(!session.is_validated);
        assert_eq!(session.validation_level, ValidationLevel::None);
    }

    #[tokio::test]
    async fn test_update_existing_session() {
        let service = IdentityService::default();

        // 创建会话
        let session_id1 = service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;

        // 使用相同指纹再次访问
        let session_id2 = service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;

        // 应该返回相同的会话ID
        assert_eq!(session_id1, session_id2);

        let session = service.get_session(&session_id1).await.unwrap();
        assert_eq!(session.access_count, 2);
    }

    #[tokio::test]
    async fn test_different_fingerprints_create_different_sessions() {
        let service = IdentityService::default();

        let session_id1 = service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;

        let session_id2 = service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_2",
                "browser_fp_1",
            )
            .await;

        // 不同设备指纹应该创建不同会话
        assert_ne!(session_id1, session_id2);

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 2);
    }

    #[tokio::test]
    async fn test_create_request() {
        let service = IdentityService::default();
        let session_id = "test_session_123";

        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("accept".to_string(), "text/html".to_string());

        let request_id = service
            .create_request(
                session_id,
                "192.168.1.100",
                "Mozilla/5.0",
                "/api/test",
                "GET",
                headers.clone(),
            )
            .await;

        assert!(request_id.starts_with("REQ_"));

        let request = service.get_request(&request_id).await.unwrap();
        assert_eq!(request.session_id, session_id);
        assert_eq!(request.ip_address, "192.168.1.100");
        assert_eq!(request.url, "/api/test");
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.headers.get("user-agent").unwrap(), "Mozilla/5.0");
    }

    #[tokio::test]
    async fn test_session_validation() {
        let service = IdentityService::default();

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        // 初始状态未验证
        assert!(!service.is_session_validated(&session_id).await);

        // 更新验证状态
        let result = service
            .update_session_validation(&session_id, true, ValidationLevel::Basic)
            .await;
        assert!(result);

        // 验证状态应该更新
        assert!(service.is_session_validated(&session_id).await);

        let session = service.get_session(&session_id).await.unwrap();
        assert!(session.is_validated);
        assert_eq!(session.validation_level, ValidationLevel::Basic);
    }

    #[tokio::test]
    async fn test_nonexistent_session_operations() {
        let service = IdentityService::default();

        // 获取不存在的会话
        let session = service.get_session("nonexistent_session").await;
        assert!(session.is_none());

        // 验证不存在的会话
        assert!(!service.is_session_validated("nonexistent_session").await);

        // 更新不存在的会话
        let result = service
            .update_session_validation("nonexistent_session", true, ValidationLevel::Basic)
            .await;
        assert!(!result);
    }
}

/// 测试指纹生成功能
#[cfg(test)]
mod fingerprint_generation_tests {
    use super::*;

    #[tokio::test]
    async fn test_device_fingerprint_generation() {
        let device_info = DeviceFingerprint {
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC+8".to_string(),
            language: "zh-CN".to_string(),
            platform: "Windows 10".to_string(),
            plugins: vec![
                "Chrome PDF Plugin".to_string(),
                "Chrome PDF Viewer".to_string(),
                "Native Client".to_string(),
            ],
            canvas_fingerprint: "canvas_hash_12345".to_string(),
            webgl_fingerprint: "webgl_hash_67890".to_string(),
        };

        let fp1 = IdentityService::generate_device_fingerprint(&device_info);
        let fp2 = IdentityService::generate_device_fingerprint(&device_info);

        // 相同输入应产生相同指纹
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);

        // 验证指纹是Base64编码
        assert!(general_purpose::STANDARD.decode(&fp1).is_ok());
    }

    #[tokio::test]
    async fn test_device_fingerprint_uniqueness() {
        let device_info1 = DeviceFingerprint {
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC+8".to_string(),
            language: "zh-CN".to_string(),
            platform: "Windows 10".to_string(),
            plugins: vec!["Chrome PDF Plugin".to_string()],
            canvas_fingerprint: "canvas_hash_1".to_string(),
            webgl_fingerprint: "webgl_hash_1".to_string(),
        };

        let device_info2 = DeviceFingerprint {
            screen_resolution: "1366x768".to_string(), // 不同分辨率
            timezone: "UTC+8".to_string(),
            language: "zh-CN".to_string(),
            platform: "Windows 10".to_string(),
            plugins: vec!["Chrome PDF Plugin".to_string()],
            canvas_fingerprint: "canvas_hash_1".to_string(),
            webgl_fingerprint: "webgl_hash_1".to_string(),
        };

        let fp1 = IdentityService::generate_device_fingerprint(&device_info1);
        let fp2 = IdentityService::generate_device_fingerprint(&device_info2);

        // 不同输入应产生不同指纹
        assert_ne!(fp1, fp2);
    }

    #[tokio::test]
    async fn test_browser_fingerprint_generation() {
        let browser_info = BrowserFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            accept_language: "zh-CN,zh;q=0.9,en;q=0.8".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
            connection: "keep-alive".to_string(),
            cache_control: "max-age=0".to_string(),
        };

        let fp1 = IdentityService::generate_browser_fingerprint(&browser_info);
        let fp2 = IdentityService::generate_browser_fingerprint(&browser_info);

        // 相同输入应产生相同指纹
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }

    #[tokio::test]
    async fn test_browser_fingerprint_from_headers() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("accept-language".to_string(), "zh-CN,zh;q=0.9".to_string());
        headers.insert("accept-encoding".to_string(), "gzip, deflate".to_string());
        headers.insert("accept".to_string(), "text/html".to_string());
        headers.insert("connection".to_string(), "keep-alive".to_string());
        headers.insert("cache-control".to_string(), "no-cache".to_string());

        let browser_fp = IdentityService::extract_browser_fingerprint_from_headers(&headers);

        assert_eq!(browser_fp.user_agent, "Mozilla/5.0");
        assert_eq!(browser_fp.accept_language, "zh-CN,zh;q=0.9");
        assert_eq!(browser_fp.accept_encoding, "gzip, deflate");
        assert_eq!(browser_fp.accept, "text/html");
        assert_eq!(browser_fp.connection, "keep-alive");
        assert_eq!(browser_fp.cache_control, "no-cache");
    }

    #[tokio::test]
    async fn test_browser_fingerprint_missing_headers() {
        let headers = HashMap::new(); // 空的headers

        let browser_fp = IdentityService::extract_browser_fingerprint_from_headers(&headers);

        // 所有字段应该为空字符串
        assert_eq!(browser_fp.user_agent, "");
        assert_eq!(browser_fp.accept_language, "");
        assert_eq!(browser_fp.accept_encoding, "");
        assert_eq!(browser_fp.accept, "");
        assert_eq!(browser_fp.connection, "");
        assert_eq!(browser_fp.cache_control, "");
    }
}

/// 测试会话管理功能
#[cfg(test)]
mod session_management_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_active_sessions_for_ip() {
        let service = IdentityService::default();

        // 创建同一IP的多个会话（不同指纹）
        service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;
        service
            .create_or_update_session(
                "192.168.1.100",
                "Chrome/91.0",
                "device_fp_2",
                "browser_fp_2",
            )
            .await;
        service
            .create_or_update_session(
                "192.168.1.101",
                "Firefox/89.0",
                "device_fp_3",
                "browser_fp_3",
            )
            .await;

        let count = service.get_active_sessions_for_ip("192.168.1.100").await;
        assert_eq!(count, 2);

        let count = service.get_active_sessions_for_ip("192.168.1.101").await;
        assert_eq!(count, 1);

        let count = service.get_active_sessions_for_ip("192.168.1.102").await;
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_get_session_requests() {
        let service = IdentityService::default();

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        // 创建多个请求
        for i in 0..3 {
            service
                .create_request(
                    &session_id,
                    "192.168.1.100",
                    "Mozilla/5.0",
                    &format!("/api/endpoint{}", i),
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        // 创建其他会话的请求
        service
            .create_request(
                "other_session",
                "192.168.1.101",
                "Chrome/91.0",
                "/api/other",
                "POST",
                HashMap::new(),
            )
            .await;

        let requests = service.get_session_requests(&session_id).await;
        assert_eq!(requests.len(), 3);

        for (i, request) in requests.iter().enumerate() {
            assert_eq!(request.session_id, session_id);
            assert_eq!(request.url, format!("/api/endpoint{}", i));
        }
    }

    #[tokio::test]
    async fn test_remove_session() {
        let service = IdentityService::default();

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        // 验证会话存在
        assert!(service.get_session(&session_id).await.is_some());

        // 删除会话
        let result = service.remove_session(&session_id).await;
        assert!(result);

        // 验证会话已被删除
        assert!(service.get_session(&session_id).await.is_none());

        // 再次删除应该返回false
        let result = service.remove_session(&session_id).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_remove_sessions_for_ip() {
        let service = IdentityService::default();

        // 创建多个会话
        service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;
        service
            .create_or_update_session(
                "192.168.1.100",
                "Chrome/91.0",
                "device_fp_2",
                "browser_fp_2",
            )
            .await;
        service
            .create_or_update_session(
                "192.168.1.101",
                "Firefox/89.0",
                "device_fp_3",
                "browser_fp_3",
            )
            .await;

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 3);

        // 删除特定IP的所有会话
        let removed_count = service.remove_sessions_for_ip("192.168.1.100").await;
        assert_eq!(removed_count, 2);

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 1);

        let count = service.get_active_sessions_for_ip("192.168.1.100").await;
        assert_eq!(count, 0);

        let count = service.get_active_sessions_for_ip("192.168.1.101").await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_get_stats() {
        let service = IdentityService::default();

        // 创建多个会话
        let session_id1 = service
            .create_or_update_session(
                "192.168.1.100",
                "Mozilla/5.0",
                "device_fp_1",
                "browser_fp_1",
            )
            .await;
        let session_id2 = service
            .create_or_update_session(
                "192.168.1.101",
                "Chrome/91.0",
                "device_fp_2",
                "browser_fp_2",
            )
            .await;
        let session_id3 = service
            .create_or_update_session(
                "192.168.1.100",
                "Firefox/89.0",
                "device_fp_3",
                "browser_fp_3",
            )
            .await;

        // 验证其中一些会话
        service
            .update_session_validation(&session_id1, true, ValidationLevel::Basic)
            .await;
        service
            .update_session_validation(&session_id2, true, ValidationLevel::Advanced)
            .await;

        // 创建一些请求
        for i in 0..5 {
            service
                .create_request(
                    &session_id1,
                    "192.168.1.100",
                    "Mozilla/5.0",
                    &format!("/api/test{}", i),
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 3);
        assert_eq!(stats.validated_sessions, 2);
        assert_eq!(stats.total_requests, 5);
        assert_eq!(stats.unique_ips, 2); // 192.168.1.100 和 192.168.1.101
    }
}

/// 测试过期和清理功能
#[cfg(test)]
mod expiry_and_cleanup_tests {
    use super::*;

    #[tokio::test]
    async fn test_session_expiry() {
        let service = IdentityService::new(0, 60); // 0小时会话TTL（立即过期）

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        // 等待一小段时间确保过期
        sleep(Duration::from_millis(100)).await;

        // 验证过期会话不被认为是已验证的
        assert!(!service.is_session_validated(&session_id).await);

        // 但是会话记录仍然存在（直到清理）
        assert!(service.get_session(&session_id).await.is_some());
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let service = IdentityService::new(0, 0); // 立即过期

        // 创建多个会话
        for i in 0..3 {
            service
                .create_or_update_session(
                    &format!("192.168.1.{}", 100 + i),
                    "Mozilla/5.0",
                    &format!("device_fp_{}", i),
                    &format!("browser_fp_{}", i),
                )
                .await;
        }

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 3);

        // 等待过期
        sleep(Duration::from_millis(100)).await;

        // 执行清理
        service.cleanup_expired().await;

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 0);
    }

    #[tokio::test]
    async fn test_cleanup_expired_requests() {
        let service = IdentityService::new(24, 0); // 24小时会话，0分钟请求（立即过期）

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        // 创建多个请求
        for i in 0..5 {
            service
                .create_request(
                    &session_id,
                    "192.168.1.100",
                    "Mozilla/5.0",
                    &format!("/api/test{}", i),
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        let stats = service.get_stats().await;
        assert_eq!(stats.total_requests, 5);

        // 等待请求过期
        sleep(Duration::from_millis(100)).await;

        // 执行清理
        service.cleanup_expired().await;

        let stats = service.get_stats().await;
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_sessions, 1); // 会话应该仍然存在
    }

    #[tokio::test]
    async fn test_partial_cleanup() {
        // 使用较短的TTL以便测试及时过期
        let service = IdentityService::new(0, 0); // 立即过期

        // 创建第一批会话和请求
        for i in 0..2 {
            let session_id = service
                .create_or_update_session(
                    &format!("192.168.1.{}", 100 + i),
                    "Mozilla/5.0",
                    &format!("device_fp_old_{}", i),
                    &format!("browser_fp_old_{}", i),
                )
                .await;

            service
                .create_request(
                    &session_id,
                    &format!("192.168.1.{}", 100 + i),
                    "Mozilla/5.0",
                    "/api/old",
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        // 等待一段时间
        sleep(Duration::from_secs(1)).await;

        // 创建第二批会话和请求
        for i in 0..2 {
            let session_id = service
                .create_or_update_session(
                    &format!("192.168.1.{}", 200 + i),
                    "Mozilla/5.0",
                    &format!("device_fp_new_{}", i),
                    &format!("browser_fp_new_{}", i),
                )
                .await;

            service
                .create_request(
                    &session_id,
                    &format!("192.168.1.{}", 200 + i),
                    "Mozilla/5.0",
                    "/api/new",
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 4);
        assert_eq!(stats.total_requests, 4);

        // 等待第一批过期
        sleep(Duration::from_secs(4)).await;

        // 清理过期项
        service.cleanup_expired().await;

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 2); // 只保留新的会话
        assert_eq!(stats.total_requests, 2); // 只保留新的请求
    }
}

/// 测试并发场景
#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::task;

    #[tokio::test]
    async fn test_concurrent_session_creation() {
        let service = Arc::new(IdentityService::default());
        let mut handles = Vec::new();

        // 并发创建多个会话
        for i in 0..10 {
            let service_clone = service.clone();
            let handle = task::spawn(async move {
                service_clone
                    .create_or_update_session(
                        &format!("192.168.1.{}", 100 + i),
                        "Mozilla/5.0",
                        &format!("device_fp_{}", i),
                        &format!("browser_fp_{}", i),
                    )
                    .await
            });
            handles.push(handle);
        }

        // 等待所有任务完成
        let mut session_ids = Vec::new();
        for handle in handles {
            let session_id = handle.await.unwrap();
            session_ids.push(session_id);
        }

        // 验证所有会话都创建成功
        assert_eq!(session_ids.len(), 10);
        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 10);

        // 验证所有ID都不重复
        let mut sorted_ids = session_ids.clone();
        sorted_ids.sort();
        sorted_ids.dedup();
        assert_eq!(sorted_ids.len(), 10);
    }

    #[tokio::test]
    async fn test_concurrent_request_creation() {
        let service = Arc::new(IdentityService::default());

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        let mut handles = Vec::new();

        // 并发创建多个请求
        for i in 0..20 {
            let service_clone = service.clone();
            let session_id_clone = session_id.clone();
            let handle = task::spawn(async move {
                service_clone
                    .create_request(
                        &session_id_clone,
                        "192.168.1.100",
                        "Mozilla/5.0",
                        &format!("/api/concurrent/{}", i),
                        "GET",
                        HashMap::new(),
                    )
                    .await
            });
            handles.push(handle);
        }

        // 等待所有任务完成
        let mut request_ids = Vec::new();
        for handle in handles {
            let request_id = handle.await.unwrap();
            request_ids.push(request_id);
        }

        // 验证所有请求都创建成功
        assert_eq!(request_ids.len(), 20);
        let stats = service.get_stats().await;
        assert_eq!(stats.total_requests, 20);

        // 验证所有ID都不重复
        let mut sorted_ids = request_ids.clone();
        sorted_ids.sort();
        sorted_ids.dedup();
        assert_eq!(sorted_ids.len(), 20);
    }

    #[tokio::test]
    async fn test_concurrent_session_updates() {
        let service = Arc::new(IdentityService::default());

        let session_id = service
            .create_or_update_session("192.168.1.100", "Mozilla/5.0", "device_fp", "browser_fp")
            .await;

        let mut handles = Vec::new();

        // 并发更新同一会话
        for i in 0..10 {
            let service_clone = service.clone();
            let session_id_clone = session_id.clone();
            let handle = task::spawn(async move {
                let validation_level = if i % 2 == 0 {
                    ValidationLevel::Basic
                } else {
                    ValidationLevel::Advanced
                };

                service_clone
                    .update_session_validation(&session_id_clone, true, validation_level)
                    .await
            });
            handles.push(handle);
        }

        // 等待所有任务完成
        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap();
            results.push(result);
        }

        // 所有更新都应该成功
        assert!(results.iter().all(|&r| r));

        let session = service.get_session(&session_id).await.unwrap();
        assert!(session.is_validated);
        // 最终的验证级别可能是Basic或Advanced，取决于最后一次更新
        assert!(
            session.validation_level == ValidationLevel::Basic
                || session.validation_level == ValidationLevel::Advanced
        );
    }

    #[tokio::test]
    async fn test_concurrent_cleanup() {
        let service = Arc::new(IdentityService::new(0, 0)); // 立即过期

        // 创建一些会话和请求
        for i in 0..5 {
            let session_id = service
                .create_or_update_session(
                    &format!("192.168.1.{}", 100 + i),
                    "Mozilla/5.0",
                    &format!("device_fp_{}", i),
                    &format!("browser_fp_{}", i),
                )
                .await;

            service
                .create_request(
                    &session_id,
                    &format!("192.168.1.{}", 100 + i),
                    "Mozilla/5.0",
                    "/api/test",
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        // 等待过期
        sleep(Duration::from_millis(100)).await;

        let mut handles = Vec::new();

        // 并发清理
        for _ in 0..3 {
            let service_clone = service.clone();
            let handle = task::spawn(async move {
                service_clone.cleanup_expired().await;
            });
            handles.push(handle);
        }

        // 等待所有清理任务完成
        for handle in handles {
            handle.await.unwrap();
        }

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.total_requests, 0);
    }
}

/// 测试验证级别枚举
#[cfg(test)]
mod validation_level_tests {
    use super::*;

    #[test]
    fn test_validation_level_variants() {
        let levels = vec![
            ValidationLevel::None,
            ValidationLevel::Basic,
            ValidationLevel::Advanced,
            ValidationLevel::Complete,
        ];

        // 测试序列化和反序列化
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: ValidationLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, deserialized);
        }
    }

    #[test]
    fn test_validation_level_equality() {
        assert_eq!(ValidationLevel::None, ValidationLevel::None);
        assert_eq!(ValidationLevel::Basic, ValidationLevel::Basic);
        assert_ne!(ValidationLevel::None, ValidationLevel::Basic);
        assert_ne!(ValidationLevel::Basic, ValidationLevel::Advanced);
    }
}

/// 性能测试
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_session_creation_performance() {
        let service = IdentityService::default();

        let start = Instant::now();

        // 创建1000个会话
        for i in 0..1000 {
            service
                .create_or_update_session(
                    &format!("192.168.{}.{}", i / 256, i % 256),
                    "Mozilla/5.0",
                    &format!("device_fp_{}", i),
                    &format!("browser_fp_{}", i),
                )
                .await;
        }

        let duration = start.elapsed();
        println!("创建1000个会话用时: {:?}", duration);

        // 会话创建应该很快
        assert!(duration.as_secs() < 5, "会话创建速度太慢: {:?}", duration);

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 1000);
    }

    #[tokio::test]
    async fn test_fingerprint_generation_performance() {
        let device_info = DeviceFingerprint {
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC+8".to_string(),
            language: "zh-CN".to_string(),
            platform: "Windows 10".to_string(),
            plugins: vec!["Chrome PDF Plugin".to_string()],
            canvas_fingerprint: "canvas_hash".to_string(),
            webgl_fingerprint: "webgl_hash".to_string(),
        };

        let start = Instant::now();

        // 生成10000个指纹
        for _ in 0..10000 {
            IdentityService::generate_device_fingerprint(&device_info);
        }

        let duration = start.elapsed();
        println!("生成10000个设备指纹用时: {:?}", duration);

        // 指纹生成应该很快
        assert!(duration.as_secs() < 2, "指纹生成速度太慢: {:?}", duration);
    }

    #[tokio::test]
    async fn test_cleanup_performance() {
        let service = IdentityService::new(0, 0); // 立即过期

        // 创建大量会话和请求
        for i in 0..2000 {
            let session_id = service
                .create_or_update_session(
                    &format!("192.168.{}.{}", i / 256, i % 256),
                    "Mozilla/5.0",
                    &format!("device_fp_{}", i),
                    &format!("browser_fp_{}", i),
                )
                .await;

            service
                .create_request(
                    &session_id,
                    &format!("192.168.{}.{}", i / 256, i % 256),
                    "Mozilla/5.0",
                    "/api/test",
                    "GET",
                    HashMap::new(),
                )
                .await;
        }

        // 等待过期
        sleep(Duration::from_millis(100)).await;

        let start = Instant::now();
        service.cleanup_expired().await;
        let duration = start.elapsed();

        println!("清理2000个过期会话和请求用时: {:?}", duration);

        // 清理应该很快
        assert!(duration.as_millis() < 1000, "清理速度太慢: {:?}", duration);

        let stats = service.get_stats().await;
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.total_requests, 0);
    }
}
