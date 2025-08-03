use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use uuid::Uuid;

#[allow(dead_code)]
pub struct CaptchaChallenge {
    pub code: String,
    pub image_data: String,
    pub created_at: SystemTime,
    pub ttl: Duration,
}

#[allow(dead_code)]
pub struct CaptchaService {
    challenges: Arc<Mutex<HashMap<String, CaptchaChallenge>>>,
    default_ttl: Duration,
}

#[allow(dead_code)]
impl CaptchaService {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            challenges: Arc::new(Mutex::new(HashMap::new())),
            default_ttl: Duration::from_secs(ttl_seconds),
        }
    }

    pub async fn generate_captcha(&self) -> Result<(String, String)> {
        // Use a seeded RNG for Send compatibility
        let mut rng = rand::rngs::StdRng::from_entropy();

        // Generate captcha characters
        let captcha_chars: String = (0..4)
            .map(|_| {
                let chars = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
                char::from(chars[rng.gen_range(0..chars.len())])
            })
            .collect();

        // Create a simple base64 image (placeholder for actual captcha image)
        let image_data_url = format!(
            "data:image/png;base64,{}",
            general_purpose::STANDARD.encode(b"placeholder_image")
        );

        let challenge_id = Uuid::new_v4().to_string();
        let challenge = CaptchaChallenge {
            code: captcha_chars.to_uppercase(),
            image_data: image_data_url.clone(),
            created_at: SystemTime::now(),
            ttl: self.default_ttl,
        };

        let mut challenges = self.challenges.lock().await;
        challenges.insert(challenge_id.clone(), challenge);

        Ok((challenge_id, image_data_url))
    }

    pub async fn verify_captcha(&self, challenge_id: &str, user_input: &str) -> Result<bool> {
        let mut challenges = self.challenges.lock().await;

        if let Some(challenge) = challenges.get(challenge_id) {
            let now = SystemTime::now();
            let elapsed = now.duration_since(challenge.created_at)?;

            if elapsed > challenge.ttl {
                challenges.remove(challenge_id);
                return Ok(false);
            }

            let is_valid = challenge.code.eq_ignore_ascii_case(user_input);

            if is_valid {
                challenges.remove(challenge_id);
            }

            Ok(is_valid)
        } else {
            Ok(false)
        }
    }

    pub async fn cleanup_expired(&self) -> Result<()> {
        let mut challenges = self.challenges.lock().await;
        let now = SystemTime::now();

        challenges.retain(
            |_, challenge| match now.duration_since(challenge.created_at) {
                Ok(elapsed) => elapsed <= challenge.ttl,
                Err(_) => false,
            },
        );

        Ok(())
    }

    pub async fn get_challenge_count(&self) -> usize {
        let challenges = self.challenges.lock().await;
        challenges.len()
    }

    #[cfg(test)]
    pub async fn get_challenge_code(&self, challenge_id: &str) -> Option<String> {
        let challenges = self.challenges.lock().await;
        challenges.get(challenge_id).map(|c| c.code.clone())
    }
}

impl Default for CaptchaService {
    fn default() -> Self {
        Self::new(300)
    }
}
