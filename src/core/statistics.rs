use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsData {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub defense_hits: u64,
    pub defense_misses: u64,
    pub ip_blocks: u64,
    pub total_requests: u64,
    pub request_by_hour: HashMap<String, u64>,
    pub blocked_ips: HashMap<String, u64>,
    pub timestamp: u64,
}

impl Default for StatisticsData {
    fn default() -> Self {
        Self {
            cache_hits: 0,
            cache_misses: 0,
            defense_hits: 0,
            defense_misses: 0,
            ip_blocks: 0,
            total_requests: 0,
            request_by_hour: HashMap::new(),
            blocked_ips: HashMap::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl StatisticsData {
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64 * 100.0
        }
    }

    pub fn defense_hit_rate(&self) -> f64 {
        let total = self.defense_hits + self.defense_misses;
        if total == 0 {
            0.0
        } else {
            self.defense_hits as f64 / total as f64 * 100.0
        }
    }
}

#[derive(Debug)]
pub struct Statistics {
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    defense_hits: AtomicU64,
    defense_misses: AtomicU64,
    ip_blocks: AtomicU64,
    total_requests: AtomicU64,
    request_by_hour: Arc<RwLock<HashMap<String, u64>>>,
    blocked_ips: Arc<RwLock<HashMap<String, u64>>>,
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            defense_hits: AtomicU64::new(0),
            defense_misses: AtomicU64::new(0),
            ip_blocks: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            request_by_hour: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn increment_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_defense_hit(&self) {
        self.defense_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_defense_miss(&self) {
        self.defense_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_ip_block(&self, ip: &str) {
        self.ip_blocks.fetch_add(1, Ordering::Relaxed);
        tokio::spawn({
            let blocked_ips = Arc::clone(&self.blocked_ips);
            let ip = ip.to_string();
            async move {
                let mut blocked_ips = blocked_ips.write().await;
                *blocked_ips.entry(ip).or_insert(0) += 1;
            }
        });
    }

    pub fn increment_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        tokio::spawn({
            let request_by_hour = Arc::clone(&self.request_by_hour);
            async move {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let hour_key = format!("{}", now / 3600);

                let mut request_by_hour = request_by_hour.write().await;
                *request_by_hour.entry(hour_key).or_insert(0) += 1;
            }
        });
    }

    pub async fn get_data(&self) -> StatisticsData {
        let request_by_hour = self.request_by_hour.read().await.clone();
        let blocked_ips = self.blocked_ips.read().await.clone();

        StatisticsData {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            defense_hits: self.defense_hits.load(Ordering::Relaxed),
            defense_misses: self.defense_misses.load(Ordering::Relaxed),
            ip_blocks: self.ip_blocks.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            request_by_hour,
            blocked_ips,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub async fn reset(&self) {
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.defense_hits.store(0, Ordering::Relaxed);
        self.defense_misses.store(0, Ordering::Relaxed);
        self.ip_blocks.store(0, Ordering::Relaxed);
        self.total_requests.store(0, Ordering::Relaxed);

        let mut request_by_hour = self.request_by_hour.write().await;
        request_by_hour.clear();

        let mut blocked_ips = self.blocked_ips.write().await;
        blocked_ips.clear();
    }

    pub async fn cleanup_old_data(&self, hours_to_keep: u64) {
        let current_hour = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 3600;

        let mut request_by_hour = self.request_by_hour.write().await;
        request_by_hour.retain(|hour_key, _| {
            if let Ok(hour) = hour_key.parse::<u64>() {
                current_hour - hour <= hours_to_keep
            } else {
                false
            }
        });
    }
}

#[derive(Debug)]
pub struct MonitoringCollector {
    statistics: Arc<Statistics>,
    collection_interval: std::time::Duration,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl MonitoringCollector {
    pub fn new(statistics: Arc<Statistics>, collection_interval_secs: u64) -> Self {
        Self {
            statistics,
            collection_interval: std::time::Duration::from_secs(collection_interval_secs),
            running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("Monitoring collector is already running".into());
            }
            *running = true;
        }

        let statistics = Arc::clone(&self.statistics);
        let interval = self.collection_interval;
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            let mut cleanup_counter = 0u64;

            while *running.read().await {
                tokio::time::sleep(interval).await;

                cleanup_counter += 1;
                if cleanup_counter % 24 == 0 {
                    statistics.cleanup_old_data(168).await;
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn collect_data(&self) -> StatisticsData {
        self.statistics.get_data().await
    }
}

pub type StatisticsManager = Arc<Statistics>;

pub fn create_statistics_manager() -> StatisticsManager {
    Arc::new(Statistics::new())
}
