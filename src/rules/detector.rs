//! 攻击检测模块，用于检测各种Web攻击

use std::sync::Arc;

use anyhow::Result;
use regex::Regex;

use crate::rules::engine::{CompiledRule, RuleEngine};
use crate::rules::model::{Rule, RuleAction, RuleSeverity, RuleTarget, RuleType};

/// 攻击检测级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionLevel {
    /// 低级别检测 - 只检测基本攻击
    Low,
    /// 中级别检测 - 检测常见攻击
    Medium,
    /// 高级别检测 - 检测高级攻击和绕过技术
    High,
}

/// 攻击检测结果
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// 是否检测到攻击
    pub detected: bool,
    /// 匹配的规则（如果有）
    pub matched_rule: Option<Arc<CompiledRule>>,
    /// 匹配的内容
    pub matched_content: Option<String>,
    /// 攻击类型
    pub attack_type: Option<String>,
}

/// 攻击检测器
pub struct AttackDetector {
    /// 规则引擎
    rule_engine: RuleEngine,
    /// 检测级别
    level: DetectionLevel,
    /// XSS检测正则表达式（按级别）
    xss_regexes: Vec<(DetectionLevel, Regex)>,
    /// SQL注入检测正则表达式（按级别）
    sql_injection_regexes: Vec<(DetectionLevel, Regex)>,
    /// SSRF检测正则表达式（按级别）
    ssrf_regexes: Vec<(DetectionLevel, Regex)>,
    /// WebShell检测正则表达式（按级别）
    webshell_regexes: Vec<(DetectionLevel, Regex)>,
}

impl AttackDetector {
    /// 创建新的攻击检测器
    pub fn new(rule_engine: RuleEngine, level: DetectionLevel) -> Result<Self> {
        let mut detector = Self {
            rule_engine,
            level,
            xss_regexes: Vec::new(),
            sql_injection_regexes: Vec::new(),
            ssrf_regexes: Vec::new(),
            webshell_regexes: Vec::new(),
        };
        
        // 初始化各种攻击的检测正则表达式
        detector.init_xss_regexes()?;
        detector.init_sql_injection_regexes()?;
        detector.init_ssrf_regexes()?;
        detector.init_webshell_regexes()?;
        
        Ok(detector)
    }
    
    /// 初始化XSS检测正则表达式
    fn init_xss_regexes(&mut self) -> Result<()> {
        // 低级别XSS检测 - 检测基本的XSS攻击
        self.xss_regexes.push((DetectionLevel::Low, Regex::new(r"(?i)<script[^>]*>[\s\S]*?<\/script>")?
        ));
        self.xss_regexes.push((DetectionLevel::Low, Regex::new(r"(?i)<img[^>]*\bonerror=")?
        ));
        
        // 中级别XSS检测 - 检测更多的XSS攻击向量
        self.xss_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)<[^>]*\b(on\w+)=")?
        ));
        self.xss_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)(javascript|vbscript|expression):")?
        ));
        
        // 高级别XSS检测 - 检测XSS绕过技术
        self.xss_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\\x[0-9a-f]{2}|&#x?[0-9a-f]+;?")?
        ));
        self.xss_regexes.push((DetectionLevel::High, Regex::new(r"(?i)document\.cookie|document\.location|document\.write|window\.location")?
        ));
        
        Ok(())
    }
    
    /// 初始化SQL注入检测正则表达式
    fn init_sql_injection_regexes(&mut self) -> Result<()> {
        // 低级别SQL注入检测 - 检测基本的SQL注入攻击
        self.sql_injection_regexes.push((DetectionLevel::Low, Regex::new(r"(?i)'\s*or\s*'\d*'\s*=\s*'\d*")?
        ));
        self.sql_injection_regexes.push((DetectionLevel::Low, Regex::new(r"(?i)\bunion\s+all\s+select\b")?
        ));
        
        // 中级别SQL注入检测 - 检测更多的SQL注入攻击向量
        self.sql_injection_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)\b(select|insert|update|delete|drop|alter|create)\b.*?\bfrom\b")?
        ));
        self.sql_injection_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i);\s*(select|insert|update|delete|drop|alter|create)\b")?
        ));
        
        // 高级别SQL注入检测 - 检测SQL注入绕过技术和时间盲注
        self.sql_injection_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\bsleep\s*\(\s*\d+\s*\)|benchmark\s*\(")?
        ));
        self.sql_injection_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\bwaitfor\s+delay\s+'")?
        ));
        
        Ok(())
    }
    
    /// 初始化SSRF检测正则表达式
    fn init_ssrf_regexes(&mut self) -> Result<()> {
        // 低级别SSRF检测 - 检测基本的SSRF攻击
        self.ssrf_regexes.push((DetectionLevel::Low, Regex::new(r"(?i)\b(https?|ftp|file|gopher|dict)://")?
        ));
        
        // 中级别SSRF检测 - 检测IP地址和本地主机
        self.ssrf_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)\b(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\b")?
        ));
        self.ssrf_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)\b(10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b")?
        ));
        
        // 高级别SSRF检测 - 检测SSRF绕过技术
        self.ssrf_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\b([0-9]+\.){3}[0-9]+\b")?
        ));
        self.ssrf_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\b0x[0-9a-f]+\b|\b[0-9]+\b")?
        ));
        
        Ok(())
    }
    
    /// 初始化WebShell检测正则表达式
    fn init_webshell_regexes(&mut self) -> Result<()> {
        // 低级别WebShell检测 - 检测基本的WebShell特征
        self.webshell_regexes.push((DetectionLevel::Low, Regex::new(r"(?i)\b(eval|system|exec|shell_exec|passthru|popen)\s*\(")?
        ));
        
        // 中级别WebShell检测 - 检测更多的WebShell特征
        self.webshell_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[")?
        ));
        self.webshell_regexes.push((DetectionLevel::Medium, Regex::new(r"(?i)\b(base64_decode|str_rot13|gzinflate|gzuncompress)\s*\(")?
        ));
        
        // 高级别WebShell检测 - 检测WebShell绕过技术
        self.webshell_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\b(preg_replace|create_function)\s*\(.*?/e")?
        ));
        self.webshell_regexes.push((DetectionLevel::High, Regex::new(r"(?i)\b(assert|call_user_func|call_user_func_array)\s*\(")?
        ));
        
        Ok(())
    }
    
    /// 设置检测级别
    pub fn set_level(&mut self, level: DetectionLevel) {
        self.level = level;
    }
    
    /// 获取当前检测级别
    pub fn get_level(&self) -> DetectionLevel {
        self.level
    }
    
    /// 检测XSS攻击
    pub fn detect_xss(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("xss") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("XSS".to_string()),
                };
            }
        }
        
        // 然后使用内置正则表达式检测
        for (level, regex) in &self.xss_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_XSS".to_string(),
                    name: format!("动态XSS检测 - 级别: {:?}", level),
                    description: "通过内置正则表达式检测到的XSS攻击".to_string(),
                    pattern: regex.to_string(),
                    rule_type: RuleType::Regex,
                    target: RuleTarget::All,
                    action: RuleAction::Block,
                    severity: match level {
                        DetectionLevel::Low => RuleSeverity::Low,
                        DetectionLevel::Medium => RuleSeverity::Medium,
                        DetectionLevel::High => RuleSeverity::High,
                    },
                    enabled: true,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                
                // 编译规则
                let compiled_rule = CompiledRule {
                    rule,
                    regex: Some(regex.clone()),
                };
                
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(Arc::new(compiled_rule)),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("XSS".to_string()),
                };
            }
        }
        
        // 未检测到XSS攻击
        DetectionResult {
            detected: false,
            matched_rule: None,
            matched_content: None,
            attack_type: None,
        }
    }
    
    /// 检测SQL注入攻击
    pub fn detect_sql_injection(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("sql") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SQL Injection".to_string()),
                };
            }
        }
        
        // 然后使用内置正则表达式检测
        for (level, regex) in &self.sql_injection_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_SQL_INJECTION".to_string(),
                    name: format!("动态SQL注入检测 - 级别: {:?}", level),
                    description: "通过内置正则表达式检测到的SQL注入攻击".to_string(),
                    pattern: regex.to_string(),
                    rule_type: RuleType::Regex,
                    target: RuleTarget::All,
                    action: RuleAction::Block,
                    severity: match level {
                        DetectionLevel::Low => RuleSeverity::Low,
                        DetectionLevel::Medium => RuleSeverity::Medium,
                        DetectionLevel::High => RuleSeverity::High,
                    },
                    enabled: true,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                
                // 编译规则
                let compiled_rule = CompiledRule {
                    rule,
                    regex: Some(regex.clone()),
                };
                
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(Arc::new(compiled_rule)),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SQL Injection".to_string()),
                };
            }
        }
        
        // 未检测到SQL注入攻击
        DetectionResult {
            detected: false,
            matched_rule: None,
            matched_content: None,
            attack_type: None,
        }
    }
    
    /// 检测SSRF攻击
    pub fn detect_ssrf(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("ssrf") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SSRF".to_string()),
                };
            }
        }
        
        // 然后使用内置正则表达式检测
        for (level, regex) in &self.ssrf_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_SSRF".to_string(),
                    name: format!("动态SSRF检测 - 级别: {:?}", level),
                    description: "通过内置正则表达式检测到的SSRF攻击".to_string(),
                    pattern: regex.to_string(),
                    rule_type: RuleType::Regex,
                    target: RuleTarget::All,
                    action: RuleAction::Block,
                    severity: match level {
                        DetectionLevel::Low => RuleSeverity::Low,
                        DetectionLevel::Medium => RuleSeverity::Medium,
                        DetectionLevel::High => RuleSeverity::High,
                    },
                    enabled: true,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                
                // 编译规则
                let compiled_rule = CompiledRule {
                    rule,
                    regex: Some(regex.clone()),
                };
                
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(Arc::new(compiled_rule)),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SSRF".to_string()),
                };
            }
        }
        
        // 未检测到SSRF攻击
        DetectionResult {
            detected: false,
            matched_rule: None,
            matched_content: None,
            attack_type: None,
        }
    }
    
    /// 检测WebShell攻击
    pub fn detect_webshell(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("webshell") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("WebShell".to_string()),
                };
            }
        }
        
        // 然后使用内置正则表达式检测
        for (level, regex) in &self.webshell_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_WEBSHELL".to_string(),
                    name: format!("动态WebShell检测 - 级别: {:?}", level),
                    description: "通过内置正则表达式检测到的WebShell攻击".to_string(),
                    pattern: regex.to_string(),
                    rule_type: RuleType::Regex,
                    target: RuleTarget::All,
                    action: RuleAction::Block,
                    severity: match level {
                        DetectionLevel::Low => RuleSeverity::Low,
                        DetectionLevel::Medium => RuleSeverity::Medium,
                        DetectionLevel::High => RuleSeverity::High,
                    },
                    enabled: true,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };
                
                // 编译规则
                let compiled_rule = CompiledRule {
                    rule,
                    regex: Some(regex.clone()),
                };
                
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(Arc::new(compiled_rule)),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("WebShell".to_string()),
                };
            }
        }
        
        // 未检测到WebShell攻击
        DetectionResult {
            detected: false,
            matched_rule: None,
            matched_content: None,
            attack_type: None,
        }
    }
    
    /// 检测自定义正则表达式
    pub fn detect_custom_regex(&self, content: &str, regex_pattern: &str) -> Result<DetectionResult> {
        // 编译正则表达式
        let regex = Regex::new(regex_pattern)?;
        
        // 检测是否匹配
        if regex.is_match(content) {
            // 创建一个匹配的规则
            let rule = Rule {
                id: "CUSTOM_REGEX".to_string(),
                name: "自定义正则表达式检测".to_string(),
                description: format!("通过自定义正则表达式 '{}' 检测到的攻击", regex_pattern),
                pattern: regex_pattern.to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::Medium, // 默认为中等严重性
                enabled: true,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            
            // 编译规则
            let compiled_rule = CompiledRule {
                rule,
                regex: Some(regex),
            };
            
            return Ok(DetectionResult {
                detected: true,
                matched_rule: Some(Arc::new(compiled_rule)),
                matched_content: Some(content.to_string()),
                attack_type: Some("Custom Regex".to_string()),
            });
        }
        
        // 未检测到匹配
        Ok(DetectionResult {
            detected: false,
            matched_rule: None,
            matched_content: None,
            attack_type: None,
        })
    }
    
    /// 检测所有类型的攻击
    pub fn detect_all(&self, content: &str) -> Vec<DetectionResult> {
        let mut results = Vec::new();
        
        // 检测XSS攻击
        let xss_result = self.detect_xss(content);
        if xss_result.detected {
            results.push(xss_result);
        }
        
        // 检测SQL注入攻击
        let sql_result = self.detect_sql_injection(content);
        if sql_result.detected {
            results.push(sql_result);
        }
        
        // 检测SSRF攻击
        let ssrf_result = self.detect_ssrf(content);
        if ssrf_result.detected {
            results.push(ssrf_result);
        }
        
        // 检测WebShell攻击
        let webshell_result = self.detect_webshell(content);
        if webshell_result.detected {
            results.push(webshell_result);
        }
        
        results
    }
}