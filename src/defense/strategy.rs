use crate::core::error::WafResult;
use crate::defense::frequency::AnomalyLevel;
use crate::defense::{DefenseAction, DefenseConfig};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct DefenseStrategy {
    config: Arc<RwLock<StrategyConfig>>,
    threat_levels: Arc<RwLock<HashMap<String, ThreatLevel>>>,
}

#[derive(Debug, Clone)]
pub struct StrategyConfig {
    pub auto_escalation: bool,
    pub deescalation_time: u64, // seconds
    pub threat_thresholds: ThreatThresholds,
}

#[derive(Debug, Clone)]
pub struct ThreatThresholds {
    pub low_to_medium: u32,
    pub medium_to_high: u32,
    pub high_to_critical: u32,
}

impl Default for ThreatThresholds {
    fn default() -> Self {
        Self {
            low_to_medium: 5,
            medium_to_high: 10,
            high_to_critical: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl DefenseStrategy {
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(StrategyConfig {
                auto_escalation: true,
                deescalation_time: 300,
                threat_thresholds: ThreatThresholds::default(),
            })),
            threat_levels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn determine_action(
        &self,
        identifier: &str,
        attack_detected: bool,
        anomaly_level: AnomalyLevel,
        current_config: &DefenseConfig,
    ) -> WafResult<DefenseAction> {
        let config = self.config.read().await;

        if !config.auto_escalation {
            // Use static configuration
            return Ok(self.get_configured_action(current_config));
        }

        // Update threat level based on current situation
        let threat_level = self
            .update_threat_level(identifier, attack_detected, anomaly_level)
            .await?;

        // Determine defense action based on threat level
        Ok(match threat_level {
            ThreatLevel::Low => DefenseAction::Allow,
            ThreatLevel::Medium => DefenseAction::FiveSecondShield,
            ThreatLevel::High => DefenseAction::ClickShield,
            ThreatLevel::Critical => DefenseAction::CaptchaShield,
        })
    }

    async fn update_threat_level(
        &self,
        identifier: &str,
        attack_detected: bool,
        anomaly_level: AnomalyLevel,
    ) -> WafResult<ThreatLevel> {
        let mut threat_levels = self.threat_levels.write().await;
        let config = self.config.read().await;

        let current_level = threat_levels
            .get(identifier)
            .cloned()
            .unwrap_or(ThreatLevel::Low);
        let mut threat_score = self.calculate_threat_score(&current_level);

        // Adjust score based on current situation
        if attack_detected {
            threat_score += 5;
        }

        match anomaly_level {
            AnomalyLevel::Normal => {}
            AnomalyLevel::Medium => threat_score += 2,
            AnomalyLevel::High => threat_score += 5,
            AnomalyLevel::Critical => threat_score += 10,
        }

        // Determine new threat level
        let new_level = if threat_score >= config.threat_thresholds.high_to_critical {
            ThreatLevel::Critical
        } else if threat_score >= config.threat_thresholds.medium_to_high {
            ThreatLevel::High
        } else if threat_score >= config.threat_thresholds.low_to_medium {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };

        threat_levels.insert(identifier.to_string(), new_level.clone());

        // Start deescalation timer if needed
        if new_level != ThreatLevel::Low {
            let identifier = identifier.to_string();
            let threat_levels = self.threat_levels.clone();
            let deescalation_time = config.deescalation_time;

            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(deescalation_time)).await;
                let mut levels = threat_levels.write().await;
                if let Some(level) = levels.get_mut(&identifier) {
                    *level = Self::deescalate_level(level);
                }
            });
        }

        Ok(new_level)
    }

    fn calculate_threat_score(&self, level: &ThreatLevel) -> u32 {
        match level {
            ThreatLevel::Low => 0,
            ThreatLevel::Medium => 5,
            ThreatLevel::High => 10,
            ThreatLevel::Critical => 20,
        }
    }

    fn deescalate_level(level: &ThreatLevel) -> ThreatLevel {
        match level {
            ThreatLevel::Critical => ThreatLevel::High,
            ThreatLevel::High => ThreatLevel::Medium,
            ThreatLevel::Medium => ThreatLevel::Low,
            ThreatLevel::Low => ThreatLevel::Low,
        }
    }

    fn get_configured_action(&self, config: &DefenseConfig) -> DefenseAction {
        if config.five_second_shield {
            DefenseAction::FiveSecondShield
        } else if config.click_shield {
            DefenseAction::ClickShield
        } else if config.captcha_shield {
            DefenseAction::CaptchaShield
        } else {
            DefenseAction::Allow
        }
    }

    pub async fn record_success(&self, identifier: &str) {
        let mut threat_levels = self.threat_levels.write().await;
        if let Some(level) = threat_levels.get_mut(identifier) {
            *level = Self::deescalate_level(level);
        }
    }

    pub async fn record_failure(&self, identifier: &str) {
        let mut threat_levels = self.threat_levels.write().await;
        if let Some(level) = threat_levels.get_mut(identifier) {
            *level = match level {
                ThreatLevel::Low => ThreatLevel::Medium,
                ThreatLevel::Medium => ThreatLevel::High,
                ThreatLevel::High => ThreatLevel::Critical,
                ThreatLevel::Critical => ThreatLevel::Critical,
            };
        } else {
            threat_levels.insert(identifier.to_string(), ThreatLevel::Medium);
        }
    }
}

pub struct DefenseFeedback {
    success_count: Arc<RwLock<HashMap<String, u64>>>,
    failure_count: Arc<RwLock<HashMap<String, u64>>>,
}

impl DefenseFeedback {
    pub fn new() -> Self {
        Self {
            success_count: Arc::new(RwLock::new(HashMap::new())),
            failure_count: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record_success(&self, defense_type: &str) {
        let mut counts = self.success_count.write().await;
        *counts.entry(defense_type.to_string()).or_insert(0) += 1;
    }

    pub async fn record_failure(&self, defense_type: &str) {
        let mut counts = self.failure_count.write().await;
        *counts.entry(defense_type.to_string()).or_insert(0) += 1;
    }

    pub async fn get_effectiveness(&self, defense_type: &str) -> f64 {
        let success = self
            .success_count
            .read()
            .await
            .get(defense_type)
            .cloned()
            .unwrap_or(0);
        let failure = self
            .failure_count
            .read()
            .await
            .get(defense_type)
            .cloned()
            .unwrap_or(0);

        let total = success + failure;
        if total == 0 {
            1.0 // Assume 100% effectiveness if no data
        } else {
            success as f64 / total as f64
        }
    }

    pub async fn get_statistics(&self) -> HashMap<String, (u64, u64, f64)> {
        let success_counts = self.success_count.read().await;
        let failure_counts = self.failure_count.read().await;

        let mut stats = HashMap::new();

        // Collect all defense types
        let mut defense_types = std::collections::HashSet::new();
        for key in success_counts.keys() {
            defense_types.insert(key.clone());
        }
        for key in failure_counts.keys() {
            defense_types.insert(key.clone());
        }

        // Calculate statistics for each type
        for defense_type in defense_types {
            let success = success_counts.get(&defense_type).cloned().unwrap_or(0);
            let failure = failure_counts.get(&defense_type).cloned().unwrap_or(0);
            let total = success + failure;
            let effectiveness = if total == 0 {
                1.0
            } else {
                success as f64 / total as f64
            };

            stats.insert(defense_type, (success, failure, effectiveness));
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_level_escalation() {
        let strategy = DefenseStrategy::new();

        // Test escalation
        let action = strategy
            .determine_action(
                "test-ip",
                true,
                AnomalyLevel::High,
                &DefenseConfig {
                    five_second_shield: true,
                    click_shield: false,
                    captcha_shield: false,
                    white_list: vec![],
                    challenge_timeout: 300,
                },
            )
            .await
            .unwrap();

        // Should escalate due to attack detected + high anomaly
        assert!(matches!(
            action,
            DefenseAction::FiveSecondShield | DefenseAction::ClickShield
        ));
    }

    #[tokio::test]
    async fn test_defense_feedback() {
        let feedback = DefenseFeedback::new();

        // Record some results
        feedback.record_success("five_second_shield").await;
        feedback.record_success("five_second_shield").await;
        feedback.record_failure("five_second_shield").await;

        // Check effectiveness
        let effectiveness = feedback.get_effectiveness("five_second_shield").await;
        assert!((effectiveness - 0.666).abs() < 0.01);

        // Check statistics
        let stats = feedback.get_statistics().await;
        let (success, failure, eff) = stats.get("five_second_shield").unwrap();
        assert_eq!(*success, 2);
        assert_eq!(*failure, 1);
        assert!((eff - 0.666).abs() < 0.01);
    }
}
