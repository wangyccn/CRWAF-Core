//! 规则引擎和攻击检测测试模块

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    
    use crate::rules::detector::{AttackDetector, DetectionLevel};
    use crate::rules::engine::RuleEngine;
    
    // 创建测试规则引擎
    fn create_test_rule_engine() -> RuleEngine {
        let mut engine = RuleEngine::new();
        
        // 如果测试规则文件存在，则加载
        let test_rules_path = Path::new("rules/test.json");
        if test_rules_path.exists() {
            if let Err(e) = engine.load_all_rules() {
                eprintln!("加载测试规则失败: {}", e);
            }
        } else {
            // 否则使用默认规则文件
            let default_path = Path::new("rules/default.json");
            if default_path.exists() {
                if let Err(e) = engine.load_all_rules() {
                    eprintln!("加载默认规则失败: {}", e);
                }
            }
        }
        
        engine
    }
    
    #[test]
    fn test_xss_detection_low() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Low).unwrap()));
        
        // 测试基本XSS攻击
        let result = detector.lock().unwrap().detect_xss("<script>alert('XSS')</script>");
        assert!(result.detected, "应该检测到基本XSS攻击");
        
        // 测试img标签XSS
        let result = detector.lock().unwrap().detect_xss("<img src=x onerror=alert('XSS')>");
        assert!(result.detected, "应该检测到img标签XSS攻击");
        
        // 测试非XSS内容
        let result = detector.lock().unwrap().detect_xss("这是正常的文本内容");
        assert!(!result.detected, "不应该检测到XSS攻击");
    }
    
    #[test]
    fn test_xss_detection_medium() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap()));
        
        // 测试事件处理器XSS
        let result = detector.lock().unwrap().detect_xss("<div onclick=alert('XSS')>");
        assert!(result.detected, "应该检测到事件处理器XSS攻击");
        
        // 测试javascript:协议
        let result = detector.lock().unwrap().detect_xss("<a href=javascript:alert('XSS')>");
        assert!(result.detected, "应该检测到javascript:协议XSS攻击");
    }
    
    #[test]
    fn test_xss_detection_high() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::High).unwrap()));
        
        // 测试编码绕过
        let result = detector.lock().unwrap().detect_xss("<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;('XSS')>");
        assert!(result.detected, "应该检测到编码绕过XSS攻击");
        
        // 测试DOM操作
        let result = detector.lock().unwrap().detect_xss("<script>document.cookie='hacked'</script>");
        assert!(result.detected, "应该检测到DOM操作XSS攻击");
    }
    
    #[test]
    fn test_sql_injection_detection() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap()));
        
        // 测试基本SQL注入
        let result = detector.lock().unwrap().detect_sql_injection("' OR '1'='1");
        assert!(result.detected, "应该检测到基本SQL注入攻击");
        
        // 测试UNION注入
        let result = detector.lock().unwrap().detect_sql_injection("UNION ALL SELECT username, password FROM users");
        assert!(result.detected, "应该检测到UNION注入攻击");
        
        // 测试时间盲注（高级别）
        let detector = Arc::new(Mutex::new(AttackDetector::new(create_test_rule_engine(), DetectionLevel::High).unwrap()));
        let result = detector.lock().unwrap().detect_sql_injection("'; WAITFOR DELAY '0:0:5'--");
        assert!(result.detected, "应该检测到时间盲注攻击");
    }
    
    #[test]
    fn test_ssrf_detection() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap()));
        
        // 测试基本SSRF
        let result = detector.lock().unwrap().detect_ssrf("http://internal-service/api");
        assert!(result.detected, "应该检测到基本SSRF攻击");
        
        // 测试IP地址SSRF
        let result = detector.lock().unwrap().detect_ssrf("http://127.0.0.1:8080/admin");
        assert!(result.detected, "应该检测到IP地址SSRF攻击");
        
        // 测试内网IP SSRF
        let result = detector.lock().unwrap().detect_ssrf("http://192.168.1.1/router");
        assert!(result.detected, "应该检测到内网IP SSRF攻击");
    }
    
    #[test]
    fn test_webshell_detection() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap()));
        
        // 测试基本WebShell
        let result = detector.lock().unwrap().detect_webshell("<?php eval($_POST['cmd']); ?>");
        assert!(result.detected, "应该检测到基本WebShell攻击");
        
        // 测试变量处理
        let result = detector.lock().unwrap().detect_webshell("<?php $cmd = $_GET['cmd']; system($cmd); ?>");
        assert!(result.detected, "应该检测到变量处理WebShell攻击");
        
        // 测试编码绕过（高级别）
        let detector = Arc::new(Mutex::new(AttackDetector::new(create_test_rule_engine(), DetectionLevel::High).unwrap()));
        let result = detector.lock().unwrap().detect_webshell("<?php assert(base64_decode('c3lzdGVtKCRfR0VUW2NtZF0pOw==')); ?>");
        assert!(result.detected, "应该检测到编码绕过WebShell攻击");
    }
    
    #[test]
    fn test_custom_regex() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap()));
        
        // 测试自定义正则表达式
        let result = detector.lock().unwrap().detect_custom_regex("admin.php?id=1", r"admin\.php\?id=\d+").unwrap();
        assert!(result.detected, "应该检测到自定义正则表达式匹配");
        
        // 测试不匹配的情况
        let result = detector.lock().unwrap().detect_custom_regex("index.php?page=about", r"admin\.php\?id=\d+").unwrap();
        assert!(!result.detected, "不应该检测到自定义正则表达式匹配");
    }
    
    #[test]
    fn test_detection_level() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Low).unwrap()));
        
        // 测试低级别检测
        assert_eq!(detector.lock().unwrap().get_level(), DetectionLevel::Low);
        
        // 测试中级别检测
        detector.lock().unwrap().set_level(DetectionLevel::Medium);
        assert_eq!(detector.lock().unwrap().get_level(), DetectionLevel::Medium);
        
        // 测试高级别检测
        detector.lock().unwrap().set_level(DetectionLevel::High);
        assert_eq!(detector.lock().unwrap().get_level(), DetectionLevel::High);
    }
    
    #[test]
    fn test_detect_all() {
        let rule_engine = create_test_rule_engine();
        let detector = Arc::new(Mutex::new(AttackDetector::new(rule_engine, DetectionLevel::Medium).unwrap()));
        
        // 测试包含多种攻击的内容
        let content = "<script>alert('XSS')</script>' OR '1'='1; http://127.0.0.1/admin";
        let results = detector.lock().unwrap().detect_all(content);
        
        // 应该检测到至少两种攻击（XSS和SQL注入）
        assert!(results.len() >= 2, "应该检测到至少两种攻击");
        
        // 验证检测到的攻击类型
        let attack_types: Vec<String> = results.iter()
            .filter_map(|r| r.attack_type.clone())
            .collect();
        
        assert!(attack_types.contains(&"XSS".to_string()), "应该检测到XSS攻击");
        assert!(attack_types.contains(&"SQL Injection".to_string()), "应该检测到SQL注入攻击");
    }
}
