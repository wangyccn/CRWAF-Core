use crate::core::error::WafResult;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct RequestRecord {
    count: u64,
    first_request: Instant,
    last_request: Instant,
}

pub struct FrequencyController {
    records: Arc<RwLock<HashMap<String, RequestRecord>>>,
    config: FrequencyConfig,
}

#[derive(Debug, Clone)]
pub struct FrequencyConfig {
    pub window_duration: Duration,
    pub max_requests: u64,
    pub block_duration: Duration,
    pub cleanup_interval: Duration,
}

impl Default for FrequencyConfig {
    fn default() -> Self {
        Self {
            window_duration: Duration::from_secs(60),
            max_requests: 100,
            block_duration: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(300),
        }
    }
}

impl FrequencyController {
    pub fn new(config: FrequencyConfig) -> Self {
        let controller = Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            config,
        };

        // Start cleanup task
        let records = controller.records.clone();
        let cleanup_interval = controller.config.cleanup_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(cleanup_interval).await;
                Self::cleanup_expired_records(&records).await;
            }
        });

        controller
    }

    pub async fn check_request(&self, identifier: &str) -> WafResult<FrequencyAction> {
        let mut records = self.records.write().await;
        let now = Instant::now();

        match records.get_mut(identifier) {
            Some(record) => {
                // Check if we're in a new window
                if now.duration_since(record.first_request) > self.config.window_duration {
                    // Reset the window
                    record.count = 1;
                    record.first_request = now;
                    record.last_request = now;
                    Ok(FrequencyAction::Allow)
                } else {
                    // Increment counter
                    record.count += 1;
                    record.last_request = now;

                    if record.count > self.config.max_requests {
                        Ok(FrequencyAction::Block(self.config.block_duration))
                    } else {
                        Ok(FrequencyAction::Allow)
                    }
                }
            }
            None => {
                // First request
                records.insert(
                    identifier.to_string(),
                    RequestRecord {
                        count: 1,
                        first_request: now,
                        last_request: now,
                    },
                );
                Ok(FrequencyAction::Allow)
            }
        }
    }

    pub async fn get_request_count(&self, identifier: &str) -> u64 {
        let records = self.records.read().await;
        records.get(identifier).map(|r| r.count).unwrap_or(0)
    }

    pub async fn reset_identifier(&self, identifier: &str) {
        let mut records = self.records.write().await;
        records.remove(identifier);
    }

    async fn cleanup_expired_records(records: &Arc<RwLock<HashMap<String, RequestRecord>>>) {
        let mut records = records.write().await;
        let now = Instant::now();

        records.retain(|_, record| {
            now.duration_since(record.last_request) < Duration::from_secs(3600)
        });
    }
}

#[derive(Debug, Clone)]
pub enum FrequencyAction {
    Allow,
    Block(Duration),
}

pub struct AnomalyDetector {
    thresholds: AnomalyThresholds,
}

#[derive(Debug, Clone)]
pub struct AnomalyThresholds {
    pub rapid_requests: u64,     // Requests in 1 second
    pub burst_requests: u64,     // Requests in 10 seconds
    pub sustained_requests: u64, // Requests in 1 minute
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            rapid_requests: 10,
            burst_requests: 50,
            sustained_requests: 200,
        }
    }
}

impl AnomalyDetector {
    pub fn new(thresholds: AnomalyThresholds) -> Self {
        Self { thresholds }
    }

    pub fn analyze_pattern(&self, request_times: &[Instant]) -> AnomalyLevel {
        if request_times.is_empty() {
            return AnomalyLevel::Normal;
        }

        let now = Instant::now();

        // Count requests in different time windows
        let rapid_count = request_times
            .iter()
            .filter(|&&time| now.duration_since(time) <= Duration::from_secs(1))
            .count() as u64;

        let burst_count = request_times
            .iter()
            .filter(|&&time| now.duration_since(time) <= Duration::from_secs(10))
            .count() as u64;

        let sustained_count = request_times
            .iter()
            .filter(|&&time| now.duration_since(time) <= Duration::from_secs(60))
            .count() as u64;

        // Determine anomaly level
        if rapid_count > self.thresholds.rapid_requests {
            AnomalyLevel::Critical
        } else if burst_count > self.thresholds.burst_requests {
            AnomalyLevel::High
        } else if sustained_count > self.thresholds.sustained_requests {
            AnomalyLevel::Medium
        } else {
            AnomalyLevel::Normal
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyLevel {
    Normal,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_frequency_control() {
        let config = FrequencyConfig {
            window_duration: Duration::from_secs(1),
            max_requests: 3,
            block_duration: Duration::from_secs(5),
            cleanup_interval: Duration::from_secs(10),
        };

        let controller = FrequencyController::new(config);

        // First three requests should be allowed
        assert!(matches!(
            controller.check_request("test-ip").await.unwrap(),
            FrequencyAction::Allow
        ));
        assert!(matches!(
            controller.check_request("test-ip").await.unwrap(),
            FrequencyAction::Allow
        ));
        assert!(matches!(
            controller.check_request("test-ip").await.unwrap(),
            FrequencyAction::Allow
        ));

        // Fourth request should be blocked
        assert!(matches!(
            controller.check_request("test-ip").await.unwrap(),
            FrequencyAction::Block(_)
        ));

        // Check request count
        assert_eq!(controller.get_request_count("test-ip").await, 4);
    }

    #[test]
    fn test_anomaly_detection() {
        let detector = AnomalyDetector::new(AnomalyThresholds::default());
        let now = Instant::now();

        // Test rapid requests
        let rapid_times: Vec<Instant> = (0..15).map(|_| now).collect();
        assert_eq!(
            detector.analyze_pattern(&rapid_times),
            AnomalyLevel::Critical
        );

        // Test normal pattern
        let normal_times = vec![
            now - Duration::from_secs(30),
            now - Duration::from_secs(20),
            now - Duration::from_secs(10),
            now,
        ];
        assert_eq!(
            detector.analyze_pattern(&normal_times),
            AnomalyLevel::Normal
        );
    }
}
