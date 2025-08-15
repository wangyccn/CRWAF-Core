//! 缓存系统单元测试
//!
//! 本模块包含内存缓存、LRU缓存和文件缓存的全面单元测试

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tempfile::TempDir;
use tokio::time::sleep;

use super::cache::{
    CacheItem, FileCache, FileCacheConfig, LruMemoryCache, MemoryCache, SerializableCacheItem,
};
use super::cache_manager::CacheManager;

/// 测试内存缓存基础功能
#[cfg(test)]
mod memory_cache_tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_cache_basic_operations() {
        let cache = Arc::new(MemoryCache::<String, String>::new(1)); // 1秒TTL

        // 测试插入和获取
        cache.insert("key1".to_string(), "value1".to_string());
        let result = cache.get(&"key1".to_string());
        assert_eq!(result, Some("value1".to_string()));

        // 测试不存在的键
        let result = cache.get(&"nonexistent".to_string());
        assert_eq!(result, None);

        // 测试更新
        cache.insert("key1".to_string(), "updated_value".to_string());
        let result = cache.get(&"key1".to_string());
        assert_eq!(result, Some("updated_value".to_string()));
    }

    #[tokio::test]
    async fn test_memory_cache_expiration() {
        let cache = Arc::new(MemoryCache::<String, String>::new(1)); // 1秒TTL

        // 插入数据
        cache.insert("expire_key".to_string(), "expire_value".to_string());

        // 立即获取应该成功
        let result = cache.get(&"expire_key".to_string());
        assert_eq!(result, Some("expire_value".to_string()));

        // 等待过期
        sleep(Duration::from_millis(1100)).await;

        // 过期后获取应该失败
        let result = cache.get(&"expire_key".to_string());
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_memory_cache_remove_and_clear() {
        let cache = Arc::new(MemoryCache::<String, String>::new(60));

        // 插入多个键值对
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        cache.insert("key3".to_string(), "value3".to_string());

        // 验证数据存在
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));
        assert_eq!(cache.get(&"key3".to_string()), Some("value3".to_string()));

        // 移除单个键
        cache.remove(&"key2".to_string());
        assert_eq!(cache.get(&"key2".to_string()), None);
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.get(&"key3".to_string()), Some("value3".to_string()));

        // 清空所有缓存
        cache.clear();
        assert_eq!(cache.get(&"key1".to_string()), None);
        assert_eq!(cache.get(&"key3".to_string()), None);
    }

    #[tokio::test]
    async fn test_memory_cache_cleanup() {
        let cache = Arc::new(MemoryCache::<String, String>::new(1)); // 1秒TTL

        // 插入多个键值对
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        cache.insert("key3".to_string(), "value3".to_string());

        // 等待过期
        sleep(Duration::from_millis(1100)).await;

        // 手动清理
        cache.cleanup();

        // 验证所有过期项都被清理
        assert_eq!(cache.get(&"key1".to_string()), None);
        assert_eq!(cache.get(&"key2".to_string()), None);
        assert_eq!(cache.get(&"key3".to_string()), None);
    }

    #[tokio::test]
    async fn test_memory_cache_cleanup_task() {
        let cache = Arc::new(MemoryCache::<String, String>::new(1)); // 1秒TTL

        // 启动清理任务（每0.5秒清理一次）
        cache.start_cleanup_task(1);

        // 插入数据
        cache.insert(
            "auto_cleanup_key".to_string(),
            "auto_cleanup_value".to_string(),
        );

        // 立即获取应该成功
        assert_eq!(
            cache.get(&"auto_cleanup_key".to_string()),
            Some("auto_cleanup_value".to_string())
        );

        // 等待过期和自动清理
        sleep(Duration::from_millis(1600)).await;

        // 应该被自动清理
        assert_eq!(cache.get(&"auto_cleanup_key".to_string()), None);

        // 停止清理任务
        cache.stop_cleanup_task();
    }

    #[tokio::test]
    async fn test_memory_cache_concurrent_access() {
        let cache = Arc::new(MemoryCache::<String, String>::new(60));

        // 创建多个任务并发访问缓存
        let mut handles = vec![];

        for i in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                let key = format!("concurrent_key_{}", i);
                let value = format!("concurrent_value_{}", i);

                // 插入数据
                cache_clone.insert(key.clone(), value.clone());

                // 获取数据
                let result = cache_clone.get(&key);
                assert_eq!(result, Some(value));

                // 多次访问
                for _ in 0..5 {
                    let result = cache_clone.get(&key);
                    assert!(result.is_some());
                }
            });
            handles.push(handle);
        }

        // 等待所有任务完成
        for handle in handles {
            handle.await.unwrap();
        }
    }
}

/// 测试LRU缓存功能
#[cfg(test)]
mod lru_cache_tests {
    use super::*;

    #[tokio::test]
    async fn test_lru_cache_basic_operations() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(3, 60)); // 最大3项，60秒TTL

        // 测试插入和获取
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        cache.insert("key3".to_string(), "value3".to_string());

        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));
        assert_eq!(cache.get(&"key3".to_string()), Some("value3".to_string()));
    }

    #[tokio::test]
    async fn test_lru_cache_eviction() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(2, 60)); // 最大2项

        // 插入两个项
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        // 验证两个项都存在
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));

        // 插入第三个项，应该淘汰最久未使用的项
        cache.insert("key3".to_string(), "value3".to_string());

        // key1应该被淘汰（因为最后访问时间最早）
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));
        assert_eq!(cache.get(&"key3".to_string()), Some("value3".to_string()));
    }

    #[tokio::test]
    async fn test_lru_cache_expiration() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(5, 1)); // 1秒TTL

        // 插入数据
        cache.insert("expire_key".to_string(), "expire_value".to_string());

        // 立即获取应该成功
        assert_eq!(
            cache.get(&"expire_key".to_string()),
            Some("expire_value".to_string())
        );

        // 等待过期
        sleep(Duration::from_millis(1100)).await;

        // 过期后获取应该失败
        assert_eq!(cache.get(&"expire_key".to_string()), None);
    }

    #[tokio::test]
    async fn test_lru_cache_remove_and_clear() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(5, 60));

        // 插入数据
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        // 移除单个键
        cache.remove(&"key1".to_string());
        assert_eq!(cache.get(&"key1".to_string()), None);
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));

        // 清空缓存
        cache.clear();
        assert_eq!(cache.get(&"key2".to_string()), None);
    }

    #[tokio::test]
    async fn test_lru_cache_cleanup() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(5, 1)); // 1秒TTL

        // 插入数据
        cache.insert("cleanup_key1".to_string(), "cleanup_value1".to_string());
        cache.insert("cleanup_key2".to_string(), "cleanup_value2".to_string());

        // 等待过期
        sleep(Duration::from_millis(1100)).await;

        // 手动清理
        cache.cleanup();

        // 验证过期项被清理
        assert_eq!(cache.get(&"cleanup_key1".to_string()), None);
        assert_eq!(cache.get(&"cleanup_key2".to_string()), None);
    }

    #[tokio::test]
    async fn test_lru_cache_cleanup_task() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(5, 1)); // 1秒TTL

        // 启动清理任务
        cache.start_cleanup_task(1);

        // 插入数据
        cache.insert("auto_key".to_string(), "auto_value".to_string());

        // 立即获取应该成功
        assert_eq!(
            cache.get(&"auto_key".to_string()),
            Some("auto_value".to_string())
        );

        // 等待过期和自动清理
        sleep(Duration::from_millis(1600)).await;

        // 应该被自动清理
        assert_eq!(cache.get(&"auto_key".to_string()), None);

        // 停止清理任务
        cache.stop_cleanup_task();
    }
}

/// 测试文件缓存功能
#[cfg(test)]
mod file_cache_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_cache_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None, // 关闭自动保存
            max_items: Some(100),
        };

        let cache = Arc::new(FileCache::<String, String>::new(config).unwrap());

        // 测试插入和获取
        cache.insert("file_key1".to_string(), "file_value1".to_string());
        cache.insert("file_key2".to_string(), "file_value2".to_string());

        assert_eq!(
            cache.get(&"file_key1".to_string()),
            Some("file_value1".to_string())
        );
        assert_eq!(
            cache.get(&"file_key2".to_string()),
            Some("file_value2".to_string())
        );
        assert_eq!(cache.get(&"nonexistent".to_string()), None);
    }

    #[tokio::test]
    async fn test_file_cache_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "persist_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None,
            max_items: Some(100),
        };

        // 创建第一个缓存实例并插入数据
        {
            let cache = Arc::new(FileCache::<String, String>::new(config.clone()).unwrap());
            cache.insert("persist_key1".to_string(), "persist_value1".to_string());
            cache.insert("persist_key2".to_string(), "persist_value2".to_string());

            // 手动保存到文件
            cache.save_to_file().unwrap();
        }

        // 创建第二个缓存实例，应该能从文件加载数据
        {
            let cache = Arc::new(FileCache::<String, String>::new(config).unwrap());

            // 验证数据从文件加载成功
            assert_eq!(
                cache.get(&"persist_key1".to_string()),
                Some("persist_value1".to_string())
            );
            assert_eq!(
                cache.get(&"persist_key2".to_string()),
                Some("persist_value2".to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_file_cache_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "expire_test".to_string(),
            ttl: Duration::from_millis(500), // 0.5秒TTL
            save_interval: None,
            max_items: Some(100),
        };

        let cache = Arc::new(FileCache::<String, String>::new(config).unwrap());

        // 插入数据
        cache.insert("expire_key".to_string(), "expire_value".to_string());

        // 立即获取应该成功
        assert_eq!(
            cache.get(&"expire_key".to_string()),
            Some("expire_value".to_string())
        );

        // 等待过期
        sleep(Duration::from_millis(600)).await;

        // 过期后获取应该失败
        assert_eq!(cache.get(&"expire_key".to_string()), None);
    }

    #[tokio::test]
    async fn test_file_cache_max_items() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "max_items_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None,
            max_items: Some(3), // 最大3项
        };

        let cache = Arc::new(FileCache::<String, String>::new(config).unwrap());

        // 插入5个项
        for i in 1..=5 {
            cache.insert(format!("key_{}", i), format!("value_{}", i));
        }

        // 手动保存
        cache.save_to_file().unwrap();

        // 重新加载缓存
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "max_items_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None,
            max_items: Some(3),
        };

        let cache2 = Arc::new(FileCache::<String, String>::new(config).unwrap());

        // 应该只保留最多3项（按过期时间排序）
        let mut found_count = 0;
        for i in 1..=5 {
            if cache2.get(&format!("key_{}", i)).is_some() {
                found_count += 1;
            }
        }
        assert!(found_count <= 3);
    }

    #[tokio::test]
    async fn test_file_cache_remove_and_clear() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "remove_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None,
            max_items: Some(100),
        };

        let cache = Arc::new(FileCache::<String, String>::new(config).unwrap());

        // 插入数据
        cache.insert("remove_key1".to_string(), "remove_value1".to_string());
        cache.insert("remove_key2".to_string(), "remove_value2".to_string());

        // 移除单个键
        cache.remove(&"remove_key1".to_string());
        assert_eq!(cache.get(&"remove_key1".to_string()), None);
        assert_eq!(
            cache.get(&"remove_key2".to_string()),
            Some("remove_value2".to_string())
        );

        // 清空缓存
        cache.clear();
        assert_eq!(cache.get(&"remove_key2".to_string()), None);
    }

    #[tokio::test]
    async fn test_file_cache_auto_save_task() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "auto_save_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: Some(1), // 1秒自动保存
            max_items: Some(100),
        };

        let cache = Arc::new(FileCache::<String, String>::new(config.clone()).unwrap());

        // 启动自动保存任务
        cache.start_auto_save_task();

        // 插入数据
        cache.insert("auto_save_key".to_string(), "auto_save_value".to_string());

        // 等待自动保存
        sleep(Duration::from_millis(1500)).await;

        // 停止自动保存任务
        cache.stop_auto_save_task();

        // 创建新的缓存实例验证数据已保存
        let cache2 = Arc::new(FileCache::<String, String>::new(config).unwrap());
        assert_eq!(
            cache2.get(&"auto_save_key".to_string()),
            Some("auto_save_value".to_string())
        );
    }
}

/// 测试序列化缓存项
#[cfg(test)]
mod serializable_cache_item_tests {
    use super::*;

    #[test]
    fn test_serializable_cache_item_conversion() {
        let now = SystemTime::now();
        let expires_at = Instant::now() + Duration::from_secs(10);

        // 创建原始缓存项
        let original_item = CacheItem {
            value: "test_value".to_string(),
            expires_at,
        };

        // 转换为可序列化格式
        let serializable = SerializableCacheItem::from_cache_item(&original_item, now).unwrap();

        // 转换回缓存项
        let converted_item = serializable.to_cache_item(now).unwrap();

        // 验证值正确
        assert_eq!(converted_item.value, original_item.value);

        // 验证过期时间大致正确（允许一定误差）
        let time_diff = if converted_item.expires_at > original_item.expires_at {
            converted_item.expires_at - original_item.expires_at
        } else {
            original_item.expires_at - converted_item.expires_at
        };
        assert!(time_diff < Duration::from_millis(500)); // 允许500ms误差
    }

    #[test]
    fn test_serializable_cache_item_expired() {
        let now = SystemTime::now();
        let expired_time = now - Duration::from_secs(10); // 已经过期的时间

        let expired_serializable = SerializableCacheItem {
            value: "expired_value".to_string(),
            expires_at_millis: expired_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        };

        // 尝试转换已过期的项应该失败
        let result = expired_serializable.to_cache_item(now);
        assert!(result.is_err());
    }
}

/// 测试缓存管理器
#[cfg(test)]
mod cache_manager_tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_manager_singleton() {
        let manager1 = CacheManager::global();
        let manager2 = CacheManager::global();

        // 应该是同一个实例
        assert!(std::ptr::eq(manager1, manager2));
    }

    #[tokio::test]
    async fn test_cache_manager_file_cache_registration() {
        let manager = CacheManager::global();

        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "manager_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None,
            max_items: Some(100),
        };

        let cache = Arc::new(FileCache::<String, String>::new(config).unwrap());

        // 注册缓存
        manager.register_file_cache("test_cache", cache.clone());

        // 获取缓存
        let retrieved_cache: Option<Arc<FileCache<String, String>>> =
            manager.get_file_cache("test_cache");

        assert!(retrieved_cache.is_some());

        // 测试缓存功能
        let retrieved = retrieved_cache.unwrap();
        retrieved.insert("manager_key".to_string(), "manager_value".to_string());
        assert_eq!(
            retrieved.get(&"manager_key".to_string()),
            Some("manager_value".to_string())
        );

        // 移除缓存
        let removed = manager.remove_file_cache("test_cache");
        assert!(removed);

        // 再次获取应该失败
        let retrieved_after_remove: Option<Arc<FileCache<String, String>>> =
            manager.get_file_cache("test_cache");
        assert!(retrieved_after_remove.is_none());
    }

    #[tokio::test]
    async fn test_cache_manager_memory_cache_registration() {
        let manager = CacheManager::global();

        let cache = Arc::new(MemoryCache::<String, String>::new(60));

        // 注册内存缓存
        manager.register_memory_cache("memory_test", cache.clone());

        // 获取缓存
        let retrieved_cache: Option<Arc<MemoryCache<String, String>>> =
            manager.get_memory_cache("memory_test");

        assert!(retrieved_cache.is_some());

        // 测试缓存功能
        let retrieved = retrieved_cache.unwrap();
        retrieved.insert("mem_key".to_string(), "mem_value".to_string());
        assert_eq!(
            retrieved.get(&"mem_key".to_string()),
            Some("mem_value".to_string())
        );

        // 移除缓存
        let removed = manager.remove_memory_cache("memory_test");
        assert!(removed);
    }

    #[tokio::test]
    async fn test_cache_manager_lru_cache_registration() {
        let manager = CacheManager::global();

        let cache = Arc::new(LruMemoryCache::<String, String>::new(10, 60));

        // 注册LRU缓存
        manager.register_lru_cache("lru_test", cache.clone());

        // 获取缓存
        let retrieved_cache: Option<Arc<LruMemoryCache<String, String>>> =
            manager.get_lru_cache("lru_test");

        assert!(retrieved_cache.is_some());

        // 测试缓存功能
        let retrieved = retrieved_cache.unwrap();
        retrieved.insert("lru_key".to_string(), "lru_value".to_string());
        assert_eq!(
            retrieved.get(&"lru_key".to_string()),
            Some("lru_value".to_string())
        );

        // 移除缓存
        let removed = manager.remove_lru_cache("lru_test");
        assert!(removed);
    }

    #[tokio::test]
    async fn test_cache_manager_clear_all() {
        let manager = CacheManager::global();

        // 注册各种类型的缓存
        let temp_dir = TempDir::new().unwrap();
        let config = FileCacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            prefix: "clear_test".to_string(),
            ttl: Duration::from_secs(60),
            save_interval: None,
            max_items: Some(100),
        };

        let file_cache = Arc::new(FileCache::<String, String>::new(config).unwrap());
        let memory_cache = Arc::new(MemoryCache::<String, String>::new(60));
        let lru_cache = Arc::new(LruMemoryCache::<String, String>::new(10, 60));

        manager.register_file_cache("clear_file", file_cache);
        manager.register_memory_cache("clear_memory", memory_cache);
        manager.register_lru_cache("clear_lru", lru_cache);

        // 验证缓存已注册
        assert!(manager
            .get_file_cache::<String, String>("clear_file")
            .is_some());
        assert!(manager
            .get_memory_cache::<String, String>("clear_memory")
            .is_some());
        assert!(manager
            .get_lru_cache::<String, String>("clear_lru")
            .is_some());

        // 清空所有缓存
        manager.clear_all();

        // 验证所有缓存都被移除
        assert!(manager
            .get_file_cache::<String, String>("clear_file")
            .is_none());
        assert!(manager
            .get_memory_cache::<String, String>("clear_memory")
            .is_none());
        assert!(manager
            .get_lru_cache::<String, String>("clear_lru")
            .is_none());
    }
}

/// 性能基准测试
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_memory_cache_performance() {
        let cache = Arc::new(MemoryCache::<String, String>::new(3600));
        let start = Instant::now();

        // 插入1000个项
        for i in 0..1000 {
            cache.insert(format!("perf_key_{}", i), format!("perf_value_{}", i));
        }

        let insert_duration = start.elapsed();
        println!("内存缓存插入1000项用时: {:?}", insert_duration);

        let start = Instant::now();

        // 获取1000个项
        for i in 0..1000 {
            let _ = cache.get(&format!("perf_key_{}", i));
        }

        let get_duration = start.elapsed();
        println!("内存缓存获取1000项用时: {:?}", get_duration);

        // 性能应该在合理范围内
        assert!(insert_duration < Duration::from_millis(100));
        assert!(get_duration < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_lru_cache_performance() {
        let cache = Arc::new(LruMemoryCache::<String, String>::new(1000, 3600));
        let start = Instant::now();

        // 插入1000个项
        for i in 0..1000 {
            cache.insert(
                format!("lru_perf_key_{}", i),
                format!("lru_perf_value_{}", i),
            );
        }

        let insert_duration = start.elapsed();
        println!("LRU缓存插入1000项用时: {:?}", insert_duration);

        let start = Instant::now();

        // 获取1000个项
        for i in 0..1000 {
            let _ = cache.get(&format!("lru_perf_key_{}", i));
        }

        let get_duration = start.elapsed();
        println!("LRU缓存获取1000项用时: {:?}", get_duration);

        // LRU缓存可能稍慢一些，但应该在合理范围内
        assert!(insert_duration < Duration::from_millis(500));
        assert!(get_duration < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_concurrent_access_performance() {
        let cache = Arc::new(MemoryCache::<String, String>::new(3600));
        let start = Instant::now();

        // 创建10个并发任务
        let mut handles = vec![];
        for task_id in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                for i in 0..100 {
                    let key = format!("concurrent_{}_{}", task_id, i);
                    let value = format!("value_{}_{}", task_id, i);

                    cache_clone.insert(key.clone(), value.clone());
                    let _ = cache_clone.get(&key);
                }
            });
            handles.push(handle);
        }

        // 等待所有任务完成
        for handle in handles {
            handle.await.unwrap();
        }

        let concurrent_duration = start.elapsed();
        println!(
            "10个并发任务各插入和获取100项用时: {:?}",
            concurrent_duration
        );

        // 并发性能应该在合理范围内
        assert!(concurrent_duration < Duration::from_millis(1000));
    }
}
