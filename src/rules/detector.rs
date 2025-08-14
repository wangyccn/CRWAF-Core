//! 攻击检测模块，用于检测各种Web攻击

use std::sync::Arc;

use anyhow::Result;
use regex::Regex;
use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::rules::engine::{CompiledRule, RuleEngine};
use crate::rules::model::{Rule, RuleAction, RuleSeverity, RuleTarget, RuleType};

/// 全局正则表达式缓存，用于避免重复编译正则
#[derive(Debug, Default)]
struct RegexCache {
    cache: DashMap<String, Regex>,
}

impl RegexCache {
    fn new() -> Self {
        Self { cache: DashMap::new() }
    }

    fn get(&self, pattern: &str) -> Result<Regex> {
        if let Some(regex) = self.cache.get(pattern) {
            Ok(regex.clone())
        } else {
            let compiled = Regex::new(pattern)?;
            self.cache.insert(pattern.to_string(), compiled.clone());
            Ok(compiled)
        }
    }
}

static REGEX_CACHE: Lazy<RegexCache> = Lazy::new(RegexCache::new);

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
    #[allow(dead_code)]
    pub matched_rule: Option<Arc<CompiledRule>>,
    /// 匹配的内容
    #[allow(dead_code)]
    pub matched_content: Option<String>,
    /// 攻击类型
    pub attack_type: Option<String>,
    /// 规则描述
    #[allow(dead_code)]
    pub description: Option<String>,
    /// 严重性
    #[allow(dead_code)]
    pub severity: Option<RuleSeverity>,
}

impl DetectionResult {
    /// 创建一个未检测到攻击的结果
    pub fn not_detected() -> Self {
        Self {
            detected: false,
            matched_rule: None,
            matched_content: None,
            attack_type: None,
            description: None,
            severity: None,
        }
    }
}

/// 攻击检测器
#[derive(Debug)]
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
    /// 是否启用上下文感知检测
    context_aware: bool,
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
            context_aware: true, // 默认启用上下文感知检测
        };

        // 初始化各种攻击的检测正则表达式
        detector.init_xss_regexes()?;
        detector.init_sql_injection_regexes()?;
        detector.init_ssrf_regexes()?;
        detector.init_webshell_regexes()?;

        Ok(detector)
    }

    /// 设置是否启用上下文感知检测
    #[allow(dead_code)]
    pub fn set_context_aware(&mut self, enabled: bool) {
        self.context_aware = enabled;
    }

    /// 获取是否启用上下文感知检测
    #[allow(dead_code)]
    pub fn is_context_aware(&self) -> bool {
        self.context_aware
    }

    /// 初始化XSS检测正则表达式
    fn init_xss_regexes(&mut self) -> Result<()> {
        // 低级别XSS检测 - 检测基本的XSS攻击
        self.xss_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r"(?i)<script[^>]*>[\s\S]*?<\/script>")?,
        ));
        self.xss_regexes
            .push((DetectionLevel::Low, REGEX_CACHE.get(r"(?i)<img[^>]*\bonerror=")?));
        self.xss_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r#"(?i)<iframe[^>]*src=["']javascript:"#)?,
        ));

        // 中级别XSS检测 - 检测更多的XSS攻击向量
        self.xss_regexes
            .push((DetectionLevel::Medium, REGEX_CACHE.get(r"(?i)<[^>]*\b(on\w+)=")?));
        self.xss_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r"(?i)(javascript|vbscript|expression):")?,
        ));
        self.xss_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r#"(?i)<object[^>]*data=["']javascript:"#)?,
        ));
        self.xss_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r#"(?i)<embed[^>]*src=["']javascript:"#)?,
        ));
        self.xss_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r#"(?i)<meta[^>]*http-equiv=["']refresh[^>]*url=["']javascript:"#)?,
        ));

        // 高级别XSS检测 - 检测XSS绕过技术和高级攻击向量
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\\x[0-9a-f]{2}|&#x?[0-9a-f]+;?")?,
        ));
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(
                r"(?i)document\.cookie|document\.location|document\.write|window\.location",
            )?,
        ));
        // HTML实体编码绕过检测
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)&(#[0-9]+|#x[0-9a-f]+|[a-z]+);?")?,
        ));
        // CSS表达式注入
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)expression\s*\(|behavior\s*:|@import|mocha:|livescript:")?,
        ));
        // SVG XSS攻击
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)<svg[^>]*><script|<svg[^>]*onload=")?,
        ));
        // 数据协议绕过
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)data:[\w\/]+;base64|data:text\/html")?,
        ));
        // 标签属性绕过
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(
                r#"(?i)<\w+[^>]*\s+(style|background|src|href|action|formaction)=["']*javascript:"#,
            )?,
        ));
        // 使用各种空白字符绕过
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)<[\s\x00-\x20]*script|javascript[\s\x00-\x20]*:")?,
        ));
        // 双重编码绕过
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)%25[0-9a-f]{2}|%2[5-6][0-9a-f]")?,
        ));
        // 使用注释绕过
        self.xss_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)<script[^>]*>[\s\S]*?<!--[\s\S]*?-->[\s\S]*?<\/script>")?,
        ));

        Ok(())
    }

    /// 初始化SQL注入检测正则表达式
    fn init_sql_injection_regexes(&mut self) -> Result<()> {
        // 低级别SQL注入检测 - 检测基本的SQL注入攻击
        self.sql_injection_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r"(?i)'\s*or\s*'\d*'\s*=\s*'\d*")?,
        ));
        self.sql_injection_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r"(?i)\bunion\s+all\s+select\b")?,
        ));

        // 中级别SQL注入检测 - 检测更多的SQL注入攻击向量
        self.sql_injection_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r"(?i)\b(select|insert|update|delete|drop|alter|create)\b.*?\bfrom\b")?,
        ));
        self.sql_injection_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r"(?i);\s*(select|insert|update|delete|drop|alter|create)\b")?,
        ));

        // 高级别SQL注入检测 - 检测SQL注入绕过技术和时间盲注
        self.sql_injection_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\bsleep\s*\(\s*\d+\s*\)|benchmark\s*\(")?,
        ));
        self.sql_injection_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\bwaitfor\s+delay\s+'")?,
        ));

        Ok(())
    }

    /// 初始化SSRF检测正则表达式
    fn init_ssrf_regexes(&mut self) -> Result<()> {
        // 低级别SSRF检测 - 检测基本的SSRF攻击
        // 只检测明确的协议指示符和内部服务名称，避免误报
        self.ssrf_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r"(?i)\b(file|gopher|dict)://")?,
        ));
        self.ssrf_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r"(?i)\binternal-service\b")?,
        ));

        // 中级别SSRF检测 - 检测IP地址和本地主机
        // 注意：移除了不支持的前瞻和后顾断言，添加对带端口的IP地址的支持
        self.ssrf_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r"(?i)\b(127\.0\.0\.1|localhost|0\.0\.0\.0|::1)(:[0-9]{1,5})?\b")?,
        ));
        self.ssrf_regexes.push((DetectionLevel::Medium, REGEX_CACHE.get(r"(?i)\b(10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{1,5})?\b")?));

        // 高级别SSRF检测 - 检测SSRF绕过技术
        // 注意：移除了不支持的前瞻和后顾断言，添加对带端口的IP地址的支持
        self.ssrf_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\b([0-9]+\.){3}[0-9]+(:[0-9]{1,5})?\b")?,
        ));
        // 十六进制IP和纯数字IP
        self.ssrf_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\b0x[0-9a-f]{8}\b|\b\d{8,10}\b")?,
        ));

        Ok(())
    }

    /// 初始化WebShell检测正则表达式
    fn init_webshell_regexes(&mut self) -> Result<()> {
        // 低级别WebShell检测 - 检测基本的WebShell特征
        self.webshell_regexes.push((
            DetectionLevel::Low,
            REGEX_CACHE.get(r"(?i)\b(eval|system|exec|shell_exec|passthru|popen)\s*\(")?,
        ));

        // 中级别WebShell检测 - 检测更多的WebShell特征
        self.webshell_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r"(?i)\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[")?,
        ));
        self.webshell_regexes.push((
            DetectionLevel::Medium,
            REGEX_CACHE.get(r"(?i)\b(base64_decode|str_rot13|gzinflate|gzuncompress)\s*\(")?,
        ));

        // 高级别WebShell检测 - 检测WebShell绕过技术
        self.webshell_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\b(preg_replace|create_function)\s*\(.*?/e")?,
        ));
        self.webshell_regexes.push((
            DetectionLevel::High,
            REGEX_CACHE.get(r"(?i)\b(assert|call_user_func|call_user_func_array)\s*\(")?,
        ));

        Ok(())
    }

    /// 设置检测级别
    #[allow(dead_code)]
    pub fn set_level(&mut self, level: DetectionLevel) {
        self.level = level;
    }

    /// 获取当前检测级别
    #[allow(dead_code)]
    pub fn get_level(&self) -> DetectionLevel {
        self.level
    }

    /// 检测XSS攻击
    #[allow(dead_code)]
    pub fn detect_xss(&self, content: &str) -> DetectionResult {
        self.detect_xss_context_aware(content, None)
    }

    /// 上下文感知的XSS检测
    pub fn detect_xss_context_aware(
        &self,
        content: &str,
        context: Option<&str>,
    ) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("xss") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule.clone()),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("XSS".to_string()),
                    description: None,
                    severity: None,
                };
            }
        }

        // 预处理内容以检测编码绕过
        let decoded_content = self.decode_xss_payload(content);

        // 根据上下文调整检测敏感度
        let effective_level = if let Some(ctx) = context {
            match ctx.to_lowercase().as_str() {
                // HTML属性上下文需要更严格的检测
                "src" | "href" | "action" | "formaction" | "style" | "background" => {
                    // 对这些属性进行更严格的检测
                    if self.is_dangerous_protocol(&decoded_content) {
                        return self.create_xss_detection_result(
                            content,
                            "危险协议检测",
                            RuleSeverity::High,
                        );
                    }
                    DetectionLevel::High
                }
                // 脚本上下文
                "script" | "onclick" | "onload" | "onerror" => DetectionLevel::High,
                // HTML内容上下文
                "html" | "innerHTML" | "outerHTML" => DetectionLevel::Medium,
                // URL参数上下文
                "url" | "query" | "param" => DetectionLevel::Medium,
                // 默认上下文
                _ => self.level,
            }
        } else {
            self.level
        };

        // 使用内置正则表达式检测
        for (level, regex) in &self.xss_regexes {
            if *level <= effective_level
                && (regex.is_match(content) || regex.is_match(&decoded_content))
            {
                return self.create_xss_detection_result(
                    content,
                    &format!("动态XSS检测 - 级别: {level:?}"),
                    match level {
                        DetectionLevel::Low => RuleSeverity::Low,
                        DetectionLevel::Medium => RuleSeverity::Medium,
                        DetectionLevel::High => RuleSeverity::High,
                    },
                );
            }
        }

        // 未检测到XSS攻击
        DetectionResult::not_detected()
    }

    /// 解码XSS载荷以检测编码绕过
    fn decode_xss_payload(&self, content: &str) -> String {
        let mut decoded = content.to_string();

        // URL解码
        if let Ok(url_decoded) = urlencoding::decode(&decoded) {
            decoded = url_decoded.to_string();
        }

        // HTML实体解码（简单实现）
        decoded = decoded
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#x27;", "'")
            .replace("&#x2F;", "/")
            .replace("&amp;", "&");

        // 十六进制解码
        let hex_regex = REGEX_CACHE
            .get(r"\\x([0-9a-fA-F]{2})")
            .unwrap();
        decoded = hex_regex
            .replace_all(&decoded, |caps: &regex::Captures| {
                if let Ok(byte_val) = u8::from_str_radix(&caps[1], 16) {
                    (byte_val as char).to_string()
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        // Unicode解码
        let unicode_regex = REGEX_CACHE
            .get(r"\\u([0-9a-fA-F]{4})")
            .unwrap();
        decoded = unicode_regex
            .replace_all(&decoded, |caps: &regex::Captures| {
                if let Ok(code_point) = u32::from_str_radix(&caps[1], 16) {
                    if let Some(ch) = char::from_u32(code_point) {
                        ch.to_string()
                    } else {
                        caps[0].to_string()
                    }
                } else {
                    caps[0].to_string()
                }
            })
            .to_string();

        decoded
    }

    /// 检测危险协议
    fn is_dangerous_protocol(&self, content: &str) -> bool {
        let dangerous_protocols = [
            "javascript:",
            "vbscript:",
            "data:",
            "about:",
            "file:",
            "ftp:",
            "jar:",
            "view-source:",
            "chrome:",
            "resource:",
        ];

        let lower_content = content.to_lowercase();
        dangerous_protocols
            .iter()
            .any(|protocol| lower_content.contains(protocol))
    }

    /// 创建XSS检测结果
    fn create_xss_detection_result(
        &self,
        content: &str,
        description: &str,
        severity: RuleSeverity,
    ) -> DetectionResult {
        let rule = Rule {
            id: "DYNAMIC_XSS_CONTEXT".to_string(),
            name: description.to_string(),
            description: "通过上下文感知检测到的XSS攻击".to_string(),
            pattern: content.to_string(),
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let compiled_rule = CompiledRule { rule, regex: None };

        DetectionResult {
            detected: true,
            matched_rule: Some(Arc::new(compiled_rule)),
            matched_content: Some(content.to_string()),
            attack_type: Some("XSS".to_string()),
            description: Some(description.to_string()),
            severity: Some(severity),
        }
    }

    /// 检测SQL注入攻击
    pub fn detect_sql_injection(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("sql") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule.clone()),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SQL Injection".to_string()),
                    description: None,
                    severity: None,
                };
            }
        }

        // 然后使用内置正则表达式检测
        for (level, regex) in &self.sql_injection_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_SQL_INJECTION".to_string(),
                    name: format!("动态SQL注入检测 - 级别: {level:?}"),
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
                    description: None,
                    severity: None,
                };
            }
        }

        // 未检测到SQL注入攻击
        DetectionResult::not_detected()
    }

    /// 检测SSRF攻击
    pub fn detect_ssrf(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("ssrf") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule.clone()),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SSRF".to_string()),
                    description: Some(rule.rule.description.clone()),
                    severity: Some(rule.rule.severity),
                };
            }
        }

        // 检查是否为Host头中的合法值
        if content.to_lowercase().starts_with("host: ") {
            // 提取Host值
            let host_value = content.split_once(":").map(|(_, v)| v.trim()).unwrap_or("");

            // 检查是否为常见的本地开发场景
            if host_value.contains("localhost") || host_value.contains("127.0.0.1") {
                // 检查是否包含端口号（常见的本地开发场景）
                if host_value.matches(":").count() == 1
                    && host_value
                        .split(":")
                        .nth(1)
                        .is_some_and(|p| p.parse::<u16>().is_ok())
                {
                    // 这可能是合法的本地开发场景，不标记为攻击
                    return DetectionResult::not_detected();
                }
            }
        }

        // 然后使用内置正则表达式检测
        for (level, regex) in &self.ssrf_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_SSRF".to_string(),
                    name: format!("动态SSRF检测 - 级别: {level:?}"),
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
                    description: Some("动态SSRF检测".to_string()),
                    severity: Some(RuleSeverity::High),
                };
            }
        }

        // 未检测到SSRF攻击
        DetectionResult::not_detected()
    }

    /// 使用自定义正则表达式检测攻击
    pub fn detect_custom_regex(&self, content: &str) -> DetectionResult {
        let rules = self.rule_engine.get_rules();
        for compiled_rule in rules {
            if compiled_rule.rule.enabled && compiled_rule.rule.rule_type == RuleType::Regex {
                if let Some(regex) = &compiled_rule.regex {
                    if regex.is_match(content) {
                        return DetectionResult {
                            detected: true,
                            matched_rule: Some(Arc::clone(compiled_rule)),
                            matched_content: Some(content.to_string()),
                            attack_type: Some(compiled_rule.rule.name.clone()),
                            description: Some(compiled_rule.rule.description.clone()),
                            severity: Some(compiled_rule.rule.severity),
                        };
                    }
                }
            }
        }

        DetectionResult::not_detected()
    }

    /// 检测WebShell攻击
    pub fn detect_webshell(&self, content: &str) -> DetectionResult {
        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("webshell") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule.clone()),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("WebShell".to_string()),
                    description: Some(rule.rule.description.clone()),
                    severity: Some(rule.rule.severity),
                };
            }
        }

        // 然后使用内置正则表达式检测
        for (level, regex) in &self.webshell_regexes {
            if *level <= self.level && regex.is_match(content) {
                // 创建一个匹配的规则
                let rule = Rule {
                    id: "DYNAMIC_WEBSHELL".to_string(),
                    name: format!("动态WebShell检测 - 级别: {level:?}"),
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
                    description: Some("动态WebShell检测".to_string()),
                    severity: Some(RuleSeverity::High),
                };
            }
        }

        // 未检测到WebShell攻击
        DetectionResult::not_detected()
    }

    /// 上下文感知的SSRF检测
    pub fn detect_ssrf_context_aware(
        &self,
        content: &str,
        context: Option<&str>,
    ) -> DetectionResult {
        // 如果未启用上下文感知检测，则使用常规检测
        if !self.context_aware {
            return self.detect_ssrf(content);
        }

        // 首先使用规则引擎检测
        if let Some(rule) = self.rule_engine.check_content(content) {
            if rule.rule.name.to_lowercase().contains("ssrf") {
                return DetectionResult {
                    detected: true,
                    matched_rule: Some(rule.clone()),
                    matched_content: Some(content.to_string()),
                    attack_type: Some("SSRF".to_string()),
                    description: Some(rule.rule.description.clone()),
                    severity: Some(rule.rule.severity),
                };
            }
        }

        // 根据上下文进行智能判断
        if let Some(ctx) = context {
            // 如果是Host头
            if ctx.to_lowercase() == "host" {
                // 检查是否为本地开发场景
                if (content.contains("localhost") || content.contains("127.0.0.1"))
                    && content.matches(":").count() == 1
                    && content
                        .split(":")
                        .nth(1)
                        .is_some_and(|p| p.parse::<u16>().is_ok())
                {
                    // 这可能是合法的本地开发场景，不标记为攻击
                    return DetectionResult::not_detected();
                }
            }
            // 如果是Referer头
            else if ctx.to_lowercase() == "referer" {
                // 检查是否为本地开发场景的Referer
                if content.contains("localhost") || content.contains("127.0.0.1") {
                    // 这可能是合法的本地开发场景，不标记为攻击
                    return DetectionResult::not_detected();
                }
            }

            // 如果是URL参数
            if ctx.to_lowercase().contains("url") || ctx.to_lowercase().contains("redirect") {
                // 对URL参数进行更严格的检查
                for (level, regex) in &self.ssrf_regexes {
                    if *level <= self.level && regex.is_match(content) {
                        // 创建一个匹配的规则
                        let rule = Rule {
                            id: "DYNAMIC_SSRF_CONTEXT".to_string(),
                            name: format!("上下文感知SSRF检测 - 级别: {level:?}, 上下文: {ctx}"),
                            description: "通过上下文感知检测到的SSRF攻击".to_string(),
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
                            description: Some("上下文感知SSRF检测".to_string()),
                            severity: Some(RuleSeverity::High),
                        };
                    }
                }
            }
        }

        // 如果没有上下文或上下文不匹配特殊处理条件，则使用常规检测
        self.detect_ssrf(content)
    }

    /// 检测所有类型的攻击
    pub fn detect_all(&self, content: &str) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // 检测XSS攻击（使用上下文感知检测）
        let xss_result = self.detect_xss_context_aware(content, None);
        if xss_result.detected {
            results.push(xss_result);
        }

        // 检测SQL注入攻击
        let sql_result = self.detect_sql_injection(content);
        if sql_result.detected {
            results.push(sql_result);
        }

        // 检测SSRF攻击（使用上下文感知检测）
        let ssrf_result = self.detect_ssrf_context_aware(content, None);
        if ssrf_result.detected {
            results.push(ssrf_result);
        }

        // 检测WebShell攻击
        let webshell_result = self.detect_webshell(content);
        if webshell_result.detected {
            results.push(webshell_result);
        }

        // 检测自定义正则攻击
        let custom_regex_result = self.detect_custom_regex(content);
        if custom_regex_result.detected {
            results.push(custom_regex_result);
        }

        results
    }
}
