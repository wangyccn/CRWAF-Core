use crate::core::error::WafResult;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CaptchaGenerator {
    pub captcha_storage: Arc<RwLock<HashMap<String, CaptchaData>>>,
}

#[derive(Debug, Clone)]
pub struct CaptchaData {
    pub answer: String,
    pub created_at: i64,
}

impl CaptchaGenerator {
    pub fn new() -> WafResult<Self> {
        Ok(Self {
            captcha_storage: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn generate_captcha(&self, captcha_id: &str) -> WafResult<String> {
        // Generate random text
        let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let text: String = (0..6)
            .map(|_| {
                let idx = (rand::random::<u32>() % chars.len() as u32) as usize;
                chars.chars().nth(idx).unwrap()
            })
            .collect();

        // Store captcha data
        let mut storage = self.captcha_storage.write().await;
        storage.insert(
            captcha_id.to_string(),
            CaptchaData {
                answer: text.clone(),
                created_at: chrono::Utc::now().timestamp(),
            },
        );

        // Clean up old captchas
        let now = chrono::Utc::now().timestamp();
        storage.retain(|_, data| now - data.created_at < 300); // 5 minutes

        Ok(text)
    }

    pub async fn verify_captcha(&self, captcha_id: &str, answer: &str) -> bool {
        let mut storage = self.captcha_storage.write().await;

        if let Some(data) = storage.get(captcha_id).cloned() {
            // Case-insensitive comparison
            let is_valid = data.answer.eq_ignore_ascii_case(answer);
            if is_valid {
                storage.remove(captcha_id);
            }
            is_valid
        } else {
            false
        }
    }
}

pub struct CaptchaShield {
    generator: Arc<CaptchaGenerator>,
}

impl CaptchaShield {
    pub fn new(generator: Arc<CaptchaGenerator>) -> Self {
        Self { generator }
    }

    pub fn generate_response_page(
        &self,
        challenge_id: &str,
        request_info: crate::defense::shield::RequestInfo,
    ) -> axum::response::Html<String> {
        let html = format!(
            r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>图片验证 - 云锁WAF</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .container {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 90%;
            text-align: center;
        }}
        
        .logo {{
            font-size: 48px;
            margin-bottom: 20px;
        }}
        
        h1 {{
            color: #333;
            font-size: 24px;
            margin-bottom: 20px;
            font-weight: 600;
        }}
        
        .info {{
            background: #f7f7f7;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
            font-size: 14px;
            line-height: 1.6;
        }}
        
        .info-item {{
            margin: 8px 0;
            display: flex;
            align-items: center;
        }}
        
        .info-label {{
            font-weight: 600;
            color: #666;
            min-width: 80px;
            margin-right: 10px;
        }}
        
        .captcha-container {{
            margin: 30px 0;
        }}
        
        .captcha-display {{
            background: #f8f9fa;
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            font-size: 32px;
            font-family: monospace;
            letter-spacing: 8px;
            text-align: center;
            user-select: none;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
        }}
        
        .input-group {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        
        .captcha-input {{
            flex: 1;
            padding: 12px 16px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }}
        
        .captcha-input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .submit-btn {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .submit-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }}
        
        .submit-btn:active {{
            transform: translateY(0);
        }}
        
        .refresh_link {{
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
            margin-top: 10px;
            display: inline-block;
        }}
        
        .refresh_link:hover {{
            text-decoration: underline;
        }}
        
        .error_message {{
            color: #e74c3c;
            font-size: 14px;
            margin-top: 10px;
            display: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️</div>
        <h1>请完成图片验证</h1>
        
        <div class="info">
            <div class="info-item">
                <span class="info-label">您的IP:</span>
                <span>{}</span>
            </div>
            <div class="info-item">
                <span class="info-label">请求地址:</span>
                <span>{}</span>
            </div>
            <div class="info-item">
                <span class="info-label">访问时间:</span>
                <span>{}</span>
            </div>
            <div class="info-item">
                <span class="info-label">目标站点:</span>
                <span>{}</span>
            </div>
        </div>
        
        <div class="captcha-container">
            <div class="captcha-display" id="captchaDisplay"></div>
            
            <div class="input-group">
                <input type="text" id="captchaInput" class="captcha-input" placeholder="请输入验证码" maxlength="6" autocomplete="off">
                <button class="submit-btn" onclick="submitCaptcha()">验证</button>
            </div>
            
            <a href="#" class="refresh_link" onclick="refreshCaptcha(); return false;">看不清？换一个</a>
            <div id="errorMessage" class="error_message">验证码错误，请重试</div>
        </div>
        
        <input type="hidden" id="challengeId" value="{}" />
    </div>
    
    <script>
        let currentCaptcha = '';
        
        async function refreshCaptcha() {{
            const challengeId = document.getElementById('challengeId').value;
            
            try {{
                const response = await fetch('/waf/captcha/' + challengeId);
                const data = await response.json();
                currentCaptcha = data.captcha;
                
                const display = document.getElementById('captchaDisplay');
                display.textContent = currentCaptcha;
                
                document.getElementById('captchaInput').value = '';
                document.getElementById('errorMessage').style.display = 'none';
            }} catch (error) {{
                console.error('Failed to load captcha:', error);
            }}
        }}
        
        async function submitCaptcha() {{
            const input = document.getElementById('captchaInput');
            const challengeId = document.getElementById('challengeId').value;
            const answer = input.value.trim();
            
            if (!answer) {{
                input.focus();
                return;
            }}
            
            try {{
                const response = await fetch('/waf/verify-captcha', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        challenge_id: challengeId,
                        answer: answer
                    }})
                }});
                
                const result = await response.json();
                
                if (result.success) {{
                    location.reload();
                }} else {{
                    document.getElementById('errorMessage').style.display = 'block';
                    refreshCaptcha();
                }}
            }} catch (error) {{
                console.error('Verification error:', error);
                document.getElementById('errorMessage').style.display = 'block';
            }}
        }}
        
        // Allow Enter key to submit
        document.getElementById('captchaInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                submitCaptcha();
            }}
        }});
        
        // Focus input on load and load initial captcha
        window.addEventListener('load', function() {{
            refreshCaptcha();
            document.getElementById('captchaInput').focus();
        }});
    </script>
</body>
</html>"##,
            request_info.ip, request_info.url, request_info.time, request_info.host, challenge_id
        );

        axum::response::Html(html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_captcha_generation() {
        let generator = CaptchaGenerator::new().unwrap();
        let text = generator.generate_captcha("test-123").await.unwrap();

        assert_eq!(text.len(), 6);
        assert!(text.chars().all(|c| c.is_alphanumeric()));
    }

    #[tokio::test]
    async fn test_captcha_verification() {
        let generator = CaptchaGenerator::new().unwrap();
        let text = generator.generate_captcha("test-456").await.unwrap();

        // Test correct answer
        assert!(generator.verify_captcha("test-456", &text).await);

        // Test incorrect answer
        assert!(!generator.verify_captcha("test-456", "WRONG").await);

        // Test already used captcha
        assert!(!generator.verify_captcha("test-456", &text).await);
    }
}
