pub mod captcha;
pub mod challenge;
pub mod frequency;
pub mod shield;
pub mod strategy;

#[cfg(test)]
pub mod defense_tests;

use crate::core::error::WafResult;
use axum::body::Body;
use axum::http::Request;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct DefenseConfig {
    pub five_second_shield: bool,
    pub click_shield: bool,
    pub captcha_shield: bool,
    pub white_list: Vec<String>,
    pub challenge_timeout: u64,
}

#[derive(Debug, Clone)]
pub struct DefenseSession {
    pub session_id: String,
    pub challenge_id: Option<String>,
    pub challenge_completed: bool,
    pub verified_at: Option<i64>,
    pub attempts: u32,
}

pub struct DefenseManager {
    sessions: Arc<RwLock<HashMap<String, DefenseSession>>>,
    config: Arc<RwLock<DefenseConfig>>,
}

impl DefenseManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(DefenseConfig {
                five_second_shield: true,
                click_shield: false,
                captcha_shield: false,
                white_list: Vec::new(),
                challenge_timeout: 300,
            })),
        }
    }

    pub async fn check_defense(&self, req: &Request<Body>) -> WafResult<DefenseAction> {
        let ip = self.extract_client_ip(req);
        let session_id = self.extract_session_id(req);

        let config = self.config.read().await;

        // Check white list
        if config.white_list.contains(&ip) {
            return Ok(DefenseAction::Allow);
        }

        // Check session status
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&session_id) {
            if session.challenge_completed {
                if let Some(verified_at) = session.verified_at {
                    let now = chrono::Utc::now().timestamp();
                    if now - verified_at < config.challenge_timeout as i64 {
                        return Ok(DefenseAction::Allow);
                    }
                }
            }
        }

        // Determine defense action based on config
        if config.five_second_shield {
            Ok(DefenseAction::FiveSecondShield)
        } else if config.click_shield {
            Ok(DefenseAction::ClickShield)
        } else if config.captcha_shield {
            Ok(DefenseAction::CaptchaShield)
        } else {
            Ok(DefenseAction::Allow)
        }
    }

    fn extract_client_ip(&self, req: &Request<Body>) -> String {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn extract_session_id(&self, req: &Request<Body>) -> String {
        req.headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                cookies
                    .split(';')
                    .find(|c| c.trim().starts_with("waf_session="))
                    .map(|c| c.trim_start_matches("waf_session=").trim().to_string())
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }

    pub async fn create_session(&self, session_id: String) -> DefenseSession {
        let session = DefenseSession {
            session_id: session_id.clone(),
            challenge_id: Some(uuid::Uuid::new_v4().to_string()),
            challenge_completed: false,
            verified_at: None,
            attempts: 0,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session.clone());

        session
    }

    pub async fn verify_challenge(
        &self,
        session_id: &str,
        challenge_response: &str,
    ) -> WafResult<bool> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.attempts += 1;

            // Verify challenge response
            if self
                .verify_challenge_response(session, challenge_response)
                .await?
            {
                session.challenge_completed = true;
                session.verified_at = Some(chrono::Utc::now().timestamp());
                return Ok(true);
            }

            // Generate new challenge after failure
            if session.attempts >= 3 {
                session.challenge_id = Some(uuid::Uuid::new_v4().to_string());
                session.attempts = 0;
            }
        }

        Ok(false)
    }

    async fn verify_challenge_response(
        &self,
        _session: &DefenseSession,
        _response: &str,
    ) -> WafResult<bool> {
        // This will be implemented by specific challenge types
        Ok(false)
    }
}

#[derive(Debug, Clone)]
pub enum DefenseAction {
    Allow,
    FiveSecondShield,
    ClickShield,
    CaptchaShield,
}
