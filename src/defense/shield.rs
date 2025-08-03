use axum::response::Html;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldChallenge {
    pub challenge_id: String,
    pub timestamp: i64,
    pub difficulty: u32,
    pub nonce: String,
}

pub struct FiveSecondShield {
    pub difficulty: u32,
}

impl FiveSecondShield {
    pub fn new() -> Self {
        Self {
            difficulty: 5, // Default difficulty level
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
        let html = format!(
            r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全验证 - 云锁WAF</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
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
        
        .progress-container {{
            background: #e0e0e0;
            border-radius: 10px;
            height: 8px;
            margin: 30px 0;
            overflow: hidden;
            position: relative;
        }}
        
        .progress-bar {{
            background: linear-gradient(90deg, #667eea, #764ba2);
            height: 100%;
            width: 0%;
            transition: width 5s linear;
            box-shadow: 0 2px 5px rgba(102, 126, 234, 0.3);
        }}
        
        .status {{
            color: #666;
            font-size: 16px;
            margin: 20px 0;
        }}
        
        .computing {{
            display: none;
            color: #667eea;
            font-size: 14px;
            margin-top: 10px;
        }}
        
        .spinner {{
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(102, 126, 234, 0.3);
            border-radius: 50%;
            border-top-color: #667eea;
            animation: spin 1s ease-in-out infinite;
            margin-right: 10px;
            vertical-align: middle;
        }}
        
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 14px;
            line-height: 1.5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️</div>
        <h1>正在进行安全验证</h1>
        
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
        
        <div class="progress-container">
            <div class="progress-bar" id="progress"></div>
        </div>
        
        <div class="status" id="status">
            正在验证您的浏览器...
        </div>
        
        <div class="computing" id="computing">
            <span class="spinner"></span>
            正在进行安全计算...
        </div>
        
        <div class="warning">
            为了保护网站安全，我们需要验证您不是恶意机器人。验证将在几秒钟内自动完成，请稍候...
        </div>
    </div>
    
    <script src="/waf/challenge.js"></script>
    <script>
        const challenge = {};
        window.addEventListener('load', function() {{
            startChallenge(challenge);
        }});
    </script>
</body>
</html>"#,
            request_info.ip, request_info.url, request_info.time, request_info.host, challenge_json
        );

        Html(html)
    }
}

pub struct ClickShield {
    pub click_areas: u32,
}

impl ClickShield {
    pub fn new() -> Self {
        Self { click_areas: 3 }
    }

    pub fn generate_response_page(
        &self,
        challenge_id: &str,
        _request_info: RequestInfo,
    ) -> Html<String> {
        let html = format!(
            r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>点击验证 - 云锁WAF</title>
    <style>
        /* Similar styling as 5-second shield */
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
        
        .click-area {{
            background: #f0f0f0;
            border: 2px dashed #ccc;
            border-radius: 10px;
            padding: 60px 20px;
            margin: 30px 0;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }}
        
        .click-area:hover {{
            background: #e8e8e8;
            border-color: #667eea;
        }}
        
        .click-area.clicked {{
            background: #e8f5e9;
            border-color: #4caf50;
        }}
        
        .click-icon {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        
        .click-text {{
            font-size: 18px;
            color: #666;
        }}
        
        .counter {{
            font-size: 14px;
            color: #999;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️</div>
        <h1>请完成点击验证</h1>
        
        <div class="info">
            <p>为了确认您是真实用户，请点击下方区域</p>
        </div>
        
        <div class="click-area" id="clickArea" onclick="handleClick()">
            <div class="click-icon">👆</div>
            <div class="click-text">点击此处验证</div>
        </div>
        
        <div class="counter" id="counter">
            点击次数: <span id="clickCount">0</span> / {}
        </div>
        
        <input type="hidden" id="challengeId" value="{}" />
    </div>
    
    <script src="/waf/click-challenge.js"></script>
</body>
</html>"#,
            self.click_areas, challenge_id
        );

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
