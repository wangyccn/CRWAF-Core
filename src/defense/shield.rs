use axum::response::Html;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldChallenge {
    pub challenge_id: String,
    pub timestamp: i64,
    pub difficulty: u32,
    pub nonce: String,
}

pub struct FiveSecondShield {
    pub difficulty: u32,
    pub template: String,
}

impl FiveSecondShield {
    pub fn new() -> Self {
        Self {
            difficulty: 5,
            template: "static/waf/5s-shield.html".to_string(),
        }
    }

    pub fn with_template(template: &str) -> Self {
        Self {
            difficulty: 5,
            template: template.to_string(),
        }
    }

    pub fn generate_challenge(&self, challenge_id: &str) -> ShieldChallenge {
        ShieldChallenge {
            challenge_id: challenge_id.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            difficulty: self.difficulty,
            nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn generate_response_page(
        &self,
        challenge: &ShieldChallenge,
        request_info: RequestInfo,
    ) -> Html<String> {
        let challenge_json = serde_json::to_string(challenge).unwrap();

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&self.template);
        let template = std::fs::read_to_string(path)
            .unwrap_or_else(|_| include_str!("../../static/waf/5s-shield.html").to_string());

        let html = template
            .replace("{{IP}}", &request_info.ip)
            .replace("{{URL}}", &request_info.url)
            .replace("{{TIME}}", &request_info.time)
            .replace("{{HOST}}", &request_info.host)
            .replace("{{CHALLENGE}}", &challenge_json);

        Html(html)
    }
}

pub struct ClickShield {
    pub click_areas: u32,
    pub template: String,
}

impl ClickShield {
    pub fn new() -> Self {
        Self {
            click_areas: 3,
            template: "static/waf/click.html".to_string(),
        }
    }

    pub fn with_template(template: &str) -> Self {
        Self {
            click_areas: 3,
            template: template.to_string(),
        }
    }

    pub fn generate_response_page(
        &self,
        challenge_id: &str,
        _request_info: RequestInfo,
    ) -> Html<String> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&self.template);
        let template = std::fs::read_to_string(path)
            .unwrap_or_else(|_| include_str!("../../static/waf/click.html").to_string());

        let html = template
            .replace("{{REQUIRED_CLICKS}}", &self.click_areas.to_string())
            .replace("{{CHALLENGE_ID}}", challenge_id);

        Html(html)
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub ip: String,
    pub url: String,
    pub time: String,
    pub host: String,
}

