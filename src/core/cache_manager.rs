//! 缓存管理器模块，用于管理不同类型的缓存实例

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use crate::core::cache::{FileCache, LruMemoryCache, MemoryCache};

/// 全局缓存管理器单例
static CACHE_MANAGER: OnceLock<CacheManager> = OnceLock::new();

/// 缓存管理器，用于存储和访问不同类型的缓存实例
pub struct CacheManager {
    /// 文件缓存实例映射表
    file_caches: Mutex<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>,
    /// 内存缓存实例映射表
    #[allow(dead_code)]
    memory_caches: Mutex<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>,
    /// LRU内存缓存实例映射表
    #[allow(dead_code)]
    lru_caches: Mutex<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>,
}

impl CacheManager {
    /// 创建新的缓存管理器
    pub fn new() -> Self {
        Self {
            file_caches: Mutex::new(HashMap::new()),
            memory_caches: Mutex::new(HashMap::new()),
            lru_caches: Mutex::new(HashMap::new()),
        }
    }

    /// 获取全局缓存管理器实例
    pub fn global() -> &'static CacheManager {
        CACHE_MANAGER.get_or_init(CacheManager::new)
    }

    /// 注册文件缓存实例
    pub fn register_file_cache<K, V>(&self, name: &str, cache: Arc<FileCache<K, V>>)
    where
        K: Eq + Hash + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
        V: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
    {
        let mut caches = self.file_caches.lock().unwrap();
        caches.insert(
            name.to_string(),
            cache as Arc<dyn std::any::Any + Send + Sync>,
        );
    }

    /// 注册内存缓存实例
    #[allow(dead_code)]
    pub fn register_memory_cache<K, V>(&self, name: &str, cache: Arc<MemoryCache<K, V>>)
    where
        K: Eq + Hash + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let mut caches = self.memory_caches.lock().unwrap();
        caches.insert(
            name.to_string(),
            cache as Arc<dyn std::any::Any + Send + Sync>,
        );
    }

    /// 注册LRU内存缓存实例
    #[allow(dead_code)]
    pub fn register_lru_cache<K, V>(&self, name: &str, cache: Arc<LruMemoryCache<K, V>>)
    where
        K: Eq + Hash + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let mut caches = self.lru_caches.lock().unwrap();
        caches.insert(
            name.to_string(),
            cache as Arc<dyn std::any::Any + Send + Sync>,
        );
    }

    /// 获取文件缓存实例
    pub fn get_file_cache<K, V>(&self, name: &str) -> Option<Arc<FileCache<K, V>>>
    where
        K: Eq + Hash + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
        V: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
    {
        let caches = self.file_caches.lock().unwrap();
        caches
            .get(name)
            .and_then(|cache| cache.clone().downcast::<FileCache<K, V>>().ok())
    }

    /// 获取内存缓存实例
    #[allow(dead_code)]
    pub fn get_memory_cache<K, V>(&self, name: &str) -> Option<Arc<MemoryCache<K, V>>>
    where
        K: Eq + Hash + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let caches = self.memory_caches.lock().unwrap();
        caches
            .get(name)
            .and_then(|cache| cache.clone().downcast::<MemoryCache<K, V>>().ok())
    }

    /// 获取LRU内存缓存实例
    #[allow(dead_code)]
    pub fn get_lru_cache<K, V>(&self, name: &str) -> Option<Arc<LruMemoryCache<K, V>>>
    where
        K: Eq + Hash + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let caches = self.lru_caches.lock().unwrap();
        caches
            .get(name)
            .and_then(|cache| cache.clone().downcast::<LruMemoryCache<K, V>>().ok())
    }

    /// 移除文件缓存实例
    #[allow(dead_code)]
    pub fn remove_file_cache(&self, name: &str) -> bool {
        let mut caches = self.file_caches.lock().unwrap();
        caches.remove(name).is_some()
    }

    /// 移除内存缓存实例
    #[allow(dead_code)]
    pub fn remove_memory_cache(&self, name: &str) -> bool {
        let mut caches = self.memory_caches.lock().unwrap();
        caches.remove(name).is_some()
    }

    /// 移除LRU内存缓存实例
    #[allow(dead_code)]
    pub fn remove_lru_cache(&self, name: &str) -> bool {
        let mut caches = self.lru_caches.lock().unwrap();
        caches.remove(name).is_some()
    }

    /// 清空所有缓存实例
    #[allow(dead_code)]
    pub fn clear_all(&self) {
        let mut file_caches = self.file_caches.lock().unwrap();
        let mut memory_caches = self.memory_caches.lock().unwrap();
        let mut lru_caches = self.lru_caches.lock().unwrap();

        file_caches.clear();
        memory_caches.clear();
        lru_caches.clear();
    }
}
