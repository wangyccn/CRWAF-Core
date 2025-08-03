use dashmap::DashMap;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::fs;
use std::hash::Hash;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::time;
use tracing::{debug, error, info, warn};

/// 带过期时间的缓存项
#[derive(Clone)]
pub struct CacheItem<V: 'static> {
    pub value: V,
    pub expires_at: Instant,
}

/// 可序列化的缓存项，用于文件缓存
#[derive(Serialize, Deserialize)]
pub struct SerializableCacheItem<V> {
    pub value: V,
    pub expires_at_secs: u64, // 从UNIX纪元开始的秒数
}

impl<V> SerializableCacheItem<V> {
    /// 从内存缓存项创建可序列化缓存项
    pub fn from_cache_item(item: &CacheItem<V>, now: SystemTime) -> io::Result<Self>
    where
        V: Clone + 'static,
    {
        // 计算过期时间（从现在开始的持续时间）
        let expires_duration = item
            .expires_at
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));

        // 计算过期时间点（UNIX时间戳）
        let expires_at = now.checked_add(expires_duration).unwrap_or(now);

        // 转换为秒数
        let expires_at_secs = expires_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();

        Ok(Self {
            value: item.value.clone(),
            expires_at_secs,
        })
    }

    /// 转换为内存缓存项
    pub fn to_cache_item(&self, now: SystemTime) -> io::Result<CacheItem<V>>
    where
        V: Clone + 'static,
    {
        // 计算过期时间点（SystemTime）
        let expires_at_system = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(self.expires_at_secs))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "无效的过期时间"))?;

        // 如果已经过期，返回错误
        if expires_at_system <= now {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "缓存项已过期"));
        }

        // 计算从现在到过期时间的持续时间
        let expires_duration = expires_at_system
            .duration_since(now)
            .map_err(io::Error::other)?;

        // 计算Instant类型的过期时间
        let expires_at = Instant::now()
            .checked_add(expires_duration)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "无法计算过期时间"))?;

        Ok(CacheItem {
            value: self.value.clone(),
            expires_at,
        })
    }
}

/// 内存缓存实现，使用DashMap提供线程安全的哈希表
#[allow(dead_code)]
pub struct MemoryCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    cache: DashMap<K, CacheItem<V>>,
    ttl: Duration,
    cleanup_running: Arc<AtomicBool>,
}

impl<K, V> MemoryCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    #[allow(dead_code)]
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            cache: DashMap::new(),
            ttl: Duration::from_secs(ttl_seconds),
            cleanup_running: Arc::new(AtomicBool::new(false)),
        }
    }

    #[allow(dead_code)]
    pub fn insert(&self, key: K, value: V) {
        let expires_at = Instant::now() + self.ttl;
        let item = CacheItem { value, expires_at };
        self.cache.insert(key, item);
    }

    #[allow(dead_code)]
    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(item) = self.cache.get(key) {
            let now = Instant::now();
            if now < item.expires_at {
                return Some(item.value.clone());
            } else {
                // 已过期，移除
                self.cache.remove(key);
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn remove(&self, key: &K) {
        self.cache.remove(key);
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// 清理过期项
    #[allow(dead_code)]
    pub fn cleanup(&self) {
        let now = Instant::now();
        let expired_keys: Vec<K> = self
            .cache
            .iter()
            .filter(|entry| now >= entry.value().expires_at)
            .map(|entry| entry.key().clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            self.cache.remove(&key);
        }

        if count > 0 {
            debug!("已清理 {} 个过期缓存项", count);
        }
    }

    /// 启动定期清理任务
    #[allow(dead_code)]
    pub fn start_cleanup_task(self: &Arc<Self>, interval_seconds: u64) {
        // 如果已经在运行，则不重复启动
        if self.cleanup_running.load(Ordering::SeqCst) {
            return;
        }

        // 标记为运行中
        self.cleanup_running.store(true, Ordering::SeqCst);

        // 克隆Arc以在任务中使用
        let cache = self.clone();
        let running = self.cleanup_running.clone();

        // 启动定期清理任务
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval_seconds));

            debug!("缓存清理任务已启动，间隔: {}秒", interval_seconds);

            loop {
                interval.tick().await;

                // 检查是否应该停止任务
                if !running.load(Ordering::SeqCst) {
                    debug!("缓存清理任务已停止");
                    break;
                }

                // 执行清理
                cache.cleanup();
            }
        });
    }

    /// 停止定期清理任务
    #[allow(dead_code)]
    pub fn stop_cleanup_task(&self) {
        self.cleanup_running.store(false, Ordering::SeqCst);
        debug!("已请求停止缓存清理任务");
    }
}

/// LRU缓存实现，使用Mutex提供线程安全
#[allow(dead_code)]
pub struct LruMemoryCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    cache: Mutex<LruCache<K, CacheItem<V>>>,
    ttl: Duration,
    cleanup_running: Arc<AtomicBool>,
}

impl<K, V> LruMemoryCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    #[allow(dead_code)]
    pub fn new(max_size: usize, ttl_seconds: u64) -> Self {
        let capacity = NonZeroUsize::new(max_size).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            ttl: Duration::from_secs(ttl_seconds),
            cleanup_running: Arc::new(AtomicBool::new(false)),
        }
    }

    #[allow(dead_code)]
    pub fn insert(&self, key: K, value: V) {
        let expires_at = Instant::now() + self.ttl;
        let item = CacheItem { value, expires_at };
        if let Ok(mut cache) = self.cache.lock() {
            cache.put(key, item);
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, key: &K) -> Option<V> {
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(item) = cache.get(key) {
                let now = Instant::now();
                if now < item.expires_at {
                    return Some(item.value.clone());
                } else {
                    // 已过期，移除
                    cache.pop(key);
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn remove(&self, key: &K) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.pop(key);
        }
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// 清理过期项
    #[allow(dead_code)]
    pub fn cleanup(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            let expired_keys: Vec<K> = cache
                .iter()
                .filter(|(_, item)| now >= item.expires_at)
                .map(|(key, _)| key.clone())
                .collect();

            let count = expired_keys.len();
            for key in expired_keys {
                cache.pop(&key);
            }

            if count > 0 {
                debug!("LRU缓存已清理 {} 个过期项", count);
            }
        }
    }

    /// 启动定期清理任务
    #[allow(dead_code)]
    pub fn start_cleanup_task(self: &Arc<Self>, interval_seconds: u64) {
        // 如果已经在运行，则不重复启动
        if self.cleanup_running.load(Ordering::SeqCst) {
            return;
        }

        // 标记为运行中
        self.cleanup_running.store(true, Ordering::SeqCst);

        // 克隆Arc以在任务中使用
        let cache = self.clone();
        let running = self.cleanup_running.clone();

        // 启动定期清理任务
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(interval_seconds));

            debug!("LRU缓存清理任务已启动，间隔: {}秒", interval_seconds);

            loop {
                interval.tick().await;

                // 检查是否应该停止任务
                if !running.load(Ordering::SeqCst) {
                    debug!("LRU缓存清理任务已停止");
                    break;
                }

                // 执行清理
                cache.cleanup();
            }
        });
    }

    /// 停止定期清理任务
    #[allow(dead_code)]
    pub fn stop_cleanup_task(&self) {
        self.cleanup_running.store(false, Ordering::SeqCst);
        debug!("已请求停止LRU缓存清理任务");
    }
}

/// 文件缓存配置
#[derive(Clone, Debug)]
pub struct FileCacheConfig {
    /// 缓存目录
    pub cache_dir: PathBuf,
    /// 缓存文件前缀
    pub prefix: String,
    /// 缓存生存时间（秒）
    pub ttl: Duration,
    /// 自动保存间隔（秒）
    pub save_interval: Option<u64>,
    /// 最大缓存条目数
    pub max_items: Option<usize>,
}

impl Default for FileCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: PathBuf::from("cache"),
            prefix: "cache".to_string(),
            ttl: Duration::from_secs(3600), // 默认1小时
            save_interval: Some(300),       // 默认5分钟
            max_items: Some(1000),          // 默认最多1000项
        }
    }
}

/// 文件缓存实现，支持将缓存持久化到文件系统
#[allow(dead_code)]
pub struct FileCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
    V: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
{
    /// 内存缓存
    memory_cache: Arc<MemoryCache<K, V>>,
    /// 缓存配置
    config: FileCacheConfig,
    /// 上次保存时间
    last_save: Mutex<SystemTime>,
    /// 是否已修改
    modified: AtomicBool,
    /// 自动保存任务是否运行
    save_task_running: Arc<AtomicBool>,
}

impl<K, V> FileCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
    V: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static,
{
    /// 创建新的文件缓存
    #[allow(dead_code)]
    pub fn new(config: FileCacheConfig) -> io::Result<Self> {
        // 确保缓存目录存在
        fs::create_dir_all(&config.cache_dir)?;

        // 创建内存缓存
        let memory_cache = Arc::new(MemoryCache::new(config.ttl.as_secs()));

        let cache = Self {
            memory_cache,
            config,
            last_save: Mutex::new(SystemTime::now()),
            modified: AtomicBool::new(false),
            save_task_running: Arc::new(AtomicBool::new(false)),
        };

        // 尝试从文件加载缓存
        if let Err(e) = cache.load_from_file() {
            warn!("无法从文件加载缓存: {}", e);
        }

        Ok(cache)
    }

    /// 获取缓存文件路径
    fn get_cache_file_path(&self) -> PathBuf {
        self.config
            .cache_dir
            .join(format!("{}.json", self.config.prefix))
    }

    /// 从文件加载缓存
    #[allow(dead_code)]
    pub fn load_from_file(&self) -> io::Result<()> {
        let file_path = self.get_cache_file_path();

        // 如果文件不存在，直接返回
        if !file_path.exists() {
            return Ok(());
        }

        // 读取文件内容
        let mut file = fs::File::open(&file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // 反序列化
        let cache_data: Vec<(K, SerializableCacheItem<V>)> = serde_json::from_str(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 当前时间
        let now = SystemTime::now();

        // 加载到内存缓存
        let mut loaded_count = 0;
        for (key, serializable_item) in cache_data {
            match serializable_item.to_cache_item(now) {
                Ok(item) => {
                    self.memory_cache.cache.insert(key, item);
                    loaded_count += 1;
                }
                Err(e) => {
                    debug!("跳过已过期或无效的缓存项: {}", e);
                }
            }
        }

        info!(
            "从文件加载了 {} 个缓存项: {}",
            loaded_count,
            file_path.display()
        );
        Ok(())
    }

    /// 保存缓存到文件
    #[allow(dead_code)]
    pub fn save_to_file(&self) -> io::Result<()> {
        // 如果没有修改，不需要保存
        if !self.modified.load(Ordering::SeqCst) {
            return Ok(());
        }

        let file_path = self.get_cache_file_path();
        let now = SystemTime::now();

        // 收集所有缓存项
        let mut cache_data = Vec::new();
        for item in self.memory_cache.cache.iter() {
            let key = item.key().clone();
            let cache_item = item.value();

            // 跳过已过期的项
            if Instant::now() >= cache_item.expires_at {
                continue;
            }

            // 转换为可序列化格式
            match SerializableCacheItem::from_cache_item(cache_item, now) {
                Ok(serializable_item) => {
                    cache_data.push((key, serializable_item));
                }
                Err(e) => {
                    warn!("无法序列化缓存项: {}", e);
                }
            }
        }

        // 如果设置了最大条目数，限制保存的数量
        if let Some(max_items) = self.config.max_items {
            if cache_data.len() > max_items {
                // 按过期时间排序，保留过期时间最晚的
                cache_data.sort_by(|a, b| b.1.expires_at_secs.cmp(&a.1.expires_at_secs));
                cache_data.truncate(max_items);
            }
        }

        // 序列化并写入文件
        let json = serde_json::to_string(&cache_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut file = fs::File::create(&file_path)?;
        file.write_all(json.as_bytes())?;

        // 更新状态
        self.modified.store(false, Ordering::SeqCst);
        if let Ok(mut last_save) = self.last_save.lock() {
            *last_save = now;
        }

        info!(
            "已保存 {} 个缓存项到文件: {}",
            cache_data.len(),
            file_path.display()
        );
        Ok(())
    }

    /// 插入缓存项
    #[allow(dead_code)]
    pub fn insert(&self, key: K, value: V) {
        self.memory_cache.insert(key, value);
        self.modified.store(true, Ordering::SeqCst);
    }

    /// 获取缓存项
    #[allow(dead_code)]
    pub fn get(&self, key: &K) -> Option<V> {
        self.memory_cache.get(key)
    }

    /// 移除缓存项
    #[allow(dead_code)]
    pub fn remove(&self, key: &K) {
        self.memory_cache.remove(key);
        self.modified.store(true, Ordering::SeqCst);
    }

    /// 清空缓存
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.memory_cache.clear();
        self.modified.store(true, Ordering::SeqCst);
    }

    /// 启动自动保存任务
    #[allow(dead_code)]
    pub fn start_auto_save_task(self: &Arc<Self>) {
        // 如果没有设置保存间隔，不启动任务
        let Some(save_interval) = self.config.save_interval else {
            return;
        };

        // 如果已经在运行，不重复启动
        if self.save_task_running.load(Ordering::SeqCst) {
            return;
        }

        // 标记为运行中
        self.save_task_running.store(true, Ordering::SeqCst);

        // 克隆Arc以在任务中使用
        let cache = self.clone();
        let running = self.save_task_running.clone();

        // 启动定期保存任务
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(save_interval));

            debug!("缓存自动保存任务已启动，间隔: {}秒", save_interval);

            loop {
                interval.tick().await;

                // 检查是否应该停止任务
                if !running.load(Ordering::SeqCst) {
                    debug!("缓存自动保存任务已停止");
                    break;
                }

                // 如果有修改，执行保存
                if cache.modified.load(Ordering::SeqCst) {
                    if let Err(e) = cache.save_to_file() {
                        error!("自动保存缓存失败: {}", e);
                    }
                }
            }
        });

        // 同时启动内存缓存的清理任务
        self.memory_cache.start_cleanup_task(save_interval);
    }

    /// 停止自动保存任务
    #[allow(dead_code)]
    pub fn stop_auto_save_task(&self) {
        self.save_task_running.store(false, Ordering::SeqCst);
        self.memory_cache.stop_cleanup_task();
        debug!("已请求停止缓存自动保存任务");
    }
}
