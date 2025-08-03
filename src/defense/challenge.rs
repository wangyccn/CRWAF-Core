use crate::core::error::{WafError, WafResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    pub challenge_id: String,
    pub timestamp: i64,
    pub difficulty: u32,
    pub nonce: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSolution {
    pub challenge_id: String,
    pub nonce: String,
    pub solution: String,
    pub iterations: u64,
}

pub struct ChallengeVerifier {
    timeout: i64,
}

impl ChallengeVerifier {
    pub fn new() -> Self {
        Self {
            timeout: 300, // 5 minutes
        }
    }

    pub fn generate_challenge(&self, challenge_id: &str, difficulty: u32) -> ChallengeData {
        let nonce = uuid::Uuid::new_v4().to_string();
        let target = self.calculate_target(difficulty);

        ChallengeData {
            challenge_id: challenge_id.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            difficulty,
            nonce,
            target,
        }
    }

    fn calculate_target(&self, difficulty: u32) -> String {
        // Generate target hash prefix based on difficulty
        // Higher difficulty = more leading zeros required
        let zeros = std::cmp::min(difficulty, 8);
        format!("{:0>width$}", "", width = zeros as usize)
    }

    pub fn verify_solution(
        &self,
        challenge: &ChallengeData,
        solution: &ChallengeSolution,
    ) -> WafResult<bool> {
        // Check challenge ID match
        if challenge.challenge_id != solution.challenge_id {
            return Ok(false);
        }

        // Check timestamp
        let now = chrono::Utc::now().timestamp();
        if now - challenge.timestamp > self.timeout {
            return Err(WafError::ValidationError("Challenge expired".to_string()));
        }

        // Verify the solution
        let input = format!("{}{}{}", challenge.nonce, solution.nonce, solution.solution);
        let hash = self.compute_hash(&input);

        // Check if hash meets difficulty requirement
        Ok(hash.starts_with(&challenge.target))
    }

    fn compute_hash(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn solve_challenge(&self, challenge: &ChallengeData) -> ChallengeSolution {
        let mut iterations = 0u64;
        let solution_nonce = uuid::Uuid::new_v4().to_string();

        loop {
            let solution = iterations.to_string();
            let input = format!("{}{}{}", challenge.nonce, solution_nonce, solution);
            let hash = self.compute_hash(&input);

            if hash.starts_with(&challenge.target) {
                return ChallengeSolution {
                    challenge_id: challenge.challenge_id.clone(),
                    nonce: solution_nonce,
                    solution,
                    iterations,
                };
            }

            iterations += 1;
        }
    }
}

#[derive(Debug, Clone)]
pub struct BehaviorVerifier {
    min_time: u64,
    max_time: u64,
    required_events: Vec<String>,
}

impl BehaviorVerifier {
    pub fn new() -> Self {
        Self {
            min_time: 3000,  // Minimum 3 seconds
            max_time: 30000, // Maximum 30 seconds
            required_events: vec![
                "mouseMove".to_string(),
                "click".to_string(),
                "keypress".to_string(),
            ],
        }
    }

    pub fn verify_behavior(&self, events: &[BehaviorEvent]) -> bool {
        // Check if all required events are present
        for required in &self.required_events {
            if !events.iter().any(|e| &e.event_type == required) {
                return false;
            }
        }

        // Check timing
        if let (Some(first), Some(last)) = (events.first(), events.last()) {
            let duration = last.timestamp - first.timestamp;
            if duration < self.min_time || duration > self.max_time {
                return false;
            }
        } else {
            return false;
        }

        // Check for suspicious patterns
        self.check_patterns(events)
    }

    fn check_patterns(&self, events: &[BehaviorEvent]) -> bool {
        // Check for bot-like behavior patterns
        let mut last_timestamp = 0u64;
        let mut intervals = Vec::new();

        for event in events {
            if last_timestamp > 0 {
                intervals.push(event.timestamp - last_timestamp);
            }
            last_timestamp = event.timestamp;
        }

        // Check if intervals are too regular (bot-like)
        if intervals.len() > 5 {
            let avg_interval = intervals.iter().sum::<u64>() / intervals.len() as u64;
            let variance = intervals
                .iter()
                .map(|&i| ((i as i64 - avg_interval as i64).pow(2)) as u64)
                .sum::<u64>()
                / intervals.len() as u64;

            // If variance is too low, it might be a bot
            if variance < 100 {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorEvent {
    pub event_type: String,
    pub timestamp: u64,
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_generation_and_verification() {
        let verifier = ChallengeVerifier::new();
        let challenge = verifier.generate_challenge("test-123", 3);

        assert_eq!(challenge.challenge_id, "test-123");
        assert_eq!(challenge.difficulty, 3);
        assert!(!challenge.nonce.is_empty());
        assert_eq!(challenge.target, "000");
    }

    #[test]
    fn test_challenge_solving() {
        let verifier = ChallengeVerifier::new();
        let challenge = verifier.generate_challenge("test-123", 2);

        let solution = verifier.solve_challenge(&challenge);
        assert_eq!(solution.challenge_id, "test-123");

        let is_valid = verifier.verify_solution(&challenge, &solution).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_behavior_verification() {
        let verifier = BehaviorVerifier::new();

        let events = vec![
            BehaviorEvent {
                event_type: "mouseMove".to_string(),
                timestamp: 1000,
                x: Some(100),
                y: Some(200),
                key: None,
            },
            BehaviorEvent {
                event_type: "click".to_string(),
                timestamp: 2500,
                x: Some(150),
                y: Some(250),
                key: None,
            },
            BehaviorEvent {
                event_type: "keypress".to_string(),
                timestamp: 4000,
                x: None,
                y: None,
                key: Some("a".to_string()),
            },
        ];

        assert!(verifier.verify_behavior(&events));
    }
}
