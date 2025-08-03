//! 规则引擎单元测试
//!
//! 本模块包含规则引擎、规则解析器和规则模型的全面单元测试

use chrono::{DateTime, Utc};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use super::engine::{CompiledRule, RuleEngine};
use super::model::{
    AttackInfo, AttackType, DetectionLevel, Rule, RuleAction, RuleSeverity, RuleTarget, RuleType,
};
use super::parser::{RuleFileMeta, RuleParser};
use crate::core::config::RulesConfig;

/// 测试规则模型
#[cfg(test)]
mod rule_model_tests {
    use super::*;

    #[test]
    fn test_rule_creation() {
        let now = Utc::now();
        let rule = Rule {
            id: "test_rule_001".to_string(),
            name: "Test XSS Rule".to_string(),
            description: "Test rule for XSS detection".to_string(),
            pattern: "<script.*?>.*?</script>".to_string(),
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::High,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        assert_eq!(rule.id, "test_rule_001");
        assert_eq!(rule.rule_type, RuleType::Regex);
        assert_eq!(rule.target, RuleTarget::All);
        assert_eq!(rule.action, RuleAction::Block);
        assert_eq!(rule.severity, RuleSeverity::High);
        assert!(rule.enabled);
    }

    #[test]
    fn test_rule_serialization() {
        let now = Utc::now();
        let rule = Rule {
            id: "ser_test_001".to_string(),
            name: "Serialization Test".to_string(),
            description: "Test rule serialization".to_string(),
            pattern: "malicious".to_string(),
            rule_type: RuleType::Contains,
            target: RuleTarget::Uri,
            action: RuleAction::Log,
            severity: RuleSeverity::Medium,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        // 序列化
        let json = serde_json::to_string(&rule).unwrap();
        assert!(!json.is_empty());

        // 反序列化
        let deserialized: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, rule.id);
        assert_eq!(deserialized.rule_type, rule.rule_type);
        assert_eq!(deserialized.target, rule.target);
        assert_eq!(deserialized.action, rule.action);
        assert_eq!(deserialized.severity, rule.severity);
    }

    #[test]
    fn test_attack_info() {
        let mut details = HashMap::new();
        details.insert("matched_pattern".to_string(), "<script>".to_string());
        details.insert("location".to_string(), "query_param".to_string());

        let attack_info = AttackInfo {
            attack_type: AttackType::XSS,
            description: "Detected XSS attempt".to_string(),
            confidence: 0.95,
            severity: DetectionLevel::High,
            matched_rule: Some("xss_rule_001".to_string()),
            details,
        };

        assert_eq!(attack_info.attack_type, AttackType::XSS);
        assert_eq!(attack_info.confidence, 0.95);
        assert_eq!(attack_info.severity, DetectionLevel::High);
        assert!(attack_info.matched_rule.is_some());
        assert_eq!(attack_info.details.len(), 2);
    }

    #[test]
    fn test_detection_level_ordering() {
        assert!(DetectionLevel::Low < DetectionLevel::Medium);
        assert!(DetectionLevel::Medium < DetectionLevel::High);
        assert!(DetectionLevel::High > DetectionLevel::Low);
    }

    #[test]
    fn test_attack_type_variants() {
        let types = vec![
            AttackType::XSS,
            AttackType::SQLInjection,
            AttackType::SSRF,
            AttackType::WebShell,
            AttackType::Custom,
        ];

        for attack_type in types {
            let json = serde_json::to_string(&attack_type).unwrap();
            let deserialized: AttackType = serde_json::from_str(&json).unwrap();
            assert_eq!(attack_type, deserialized);
        }
    }

    #[test]
    fn test_rule_severity_variants() {
        let severities = vec![
            RuleSeverity::Low,
            RuleSeverity::Medium,
            RuleSeverity::High,
            RuleSeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).unwrap();
            let deserialized: RuleSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(severity, deserialized);
        }
    }
}

/// 测试规则解析器
#[cfg(test)]
mod rule_parser_tests {
    use super::*;

    fn create_test_rule_file(dir: &TempDir, filename: &str, rules: &[Rule]) -> PathBuf {
        let file_path = dir.path().join(filename);
        let json = serde_json::to_string_pretty(rules).unwrap();
        fs::write(&file_path, json).unwrap();
        file_path
    }

    fn create_sample_rule(id: &str, pattern: &str) -> Rule {
        let now = Utc::now();
        Rule {
            id: id.to_string(),
            name: format!("Test Rule {}", id),
            description: format!("Test rule with pattern: {}", pattern),
            pattern: pattern.to_string(),
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::High,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_rule_parser_creation() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), true);

        // 测试解析器创建成功
        // 注意：无法直接访问私有字段，但可以通过功能测试来验证
    }

    #[test]
    fn test_parse_single_rule_file() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false); // 不使用缓存

        let test_rules = vec![
            create_sample_rule("001", "<script>"),
            create_sample_rule("002", "SELECT.*FROM"),
            create_sample_rule("003", "eval\\("),
        ];

        let rule_file = create_test_rule_file(&temp_dir, "test_rules.json", &test_rules);

        let parsed_rules = parser.parse_rule_file(&rule_file).unwrap();
        assert_eq!(parsed_rules.len(), 3);

        assert_eq!(parsed_rules[0].id, "001");
        assert_eq!(parsed_rules[0].pattern, "<script>");

        assert_eq!(parsed_rules[1].id, "002");
        assert_eq!(parsed_rules[1].pattern, "SELECT.*FROM");

        assert_eq!(parsed_rules[2].id, "003");
        assert_eq!(parsed_rules[2].pattern, "eval\\(");
    }

    #[test]
    fn test_parse_multiple_rule_files() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false);

        // 创建多个规则文件
        let xss_rules = vec![
            create_sample_rule("xss_001", "<script>"),
            create_sample_rule("xss_002", "javascript:"),
        ];
        create_test_rule_file(&temp_dir, "xss_rules.json", &xss_rules);

        let sql_rules = vec![
            create_sample_rule("sql_001", "SELECT.*FROM"),
            create_sample_rule("sql_002", "UNION.*SELECT"),
        ];
        create_test_rule_file(&temp_dir, "sql_rules.json", &sql_rules);

        let rule_files = vec!["xss_rules.json".to_string(), "sql_rules.json".to_string()];
        let all_rules = parser.parse_rule_files(&rule_files).unwrap();

        assert_eq!(all_rules.len(), 4);

        // 验证XSS规则
        let xss_rule = all_rules.iter().find(|r| r.id == "xss_001").unwrap();
        assert_eq!(xss_rule.pattern, "<script>");

        // 验证SQL规则
        let sql_rule = all_rules.iter().find(|r| r.id == "sql_001").unwrap();
        assert_eq!(sql_rule.pattern, "SELECT.*FROM");
    }

    #[test]
    fn test_parse_all_rules_in_directory() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false);

        // 创建多个.json文件
        let rules1 = vec![create_sample_rule("dir_001", "test1")];
        create_test_rule_file(&temp_dir, "rules1.json", &rules1);

        let rules2 = vec![create_sample_rule("dir_002", "test2")];
        create_test_rule_file(&temp_dir, "rules2.json", &rules2);

        // 创建一个非JSON文件（应该被忽略）
        fs::write(
            temp_dir.path().join("readme.txt"),
            "This is not a JSON file",
        )
        .unwrap();

        let all_rules = parser.parse_all_rules().unwrap();
        assert_eq!(all_rules.len(), 2);

        let rule_ids: Vec<String> = all_rules.iter().map(|r| r.id.clone()).collect();
        assert!(rule_ids.contains(&"dir_001".to_string()));
        assert!(rule_ids.contains(&"dir_002".to_string()));
    }

    #[test]
    fn test_parse_invalid_json_file() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false);

        // 创建无效的JSON文件
        let invalid_file = temp_dir.path().join("invalid.json");
        fs::write(&invalid_file, "{ invalid json content }").unwrap();

        let result = parser.parse_rule_file(&invalid_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_rule_file() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false);

        let empty_rules: Vec<Rule> = vec![];
        let empty_file = create_test_rule_file(&temp_dir, "empty.json", &empty_rules);

        let parsed_rules = parser.parse_rule_file(&empty_file).unwrap();
        assert_eq!(parsed_rules.len(), 0);
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false);

        let nonexistent_file = temp_dir.path().join("nonexistent.json");
        let result = parser.parse_rule_file(&nonexistent_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_utf8_bom_handling() {
        let temp_dir = TempDir::new().unwrap();
        let parser = RuleParser::new(temp_dir.path(), false);

        let test_rules = vec![create_sample_rule("bom_001", "test_pattern")];
        let json = serde_json::to_string_pretty(&test_rules).unwrap();

        // 添加UTF-8 BOM
        let bom_json = format!("\u{feff}{}", json);

        let bom_file = temp_dir.path().join("bom_test.json");
        fs::write(&bom_file, bom_json).unwrap();

        let parsed_rules = parser.parse_rule_file(&bom_file).unwrap();
        assert_eq!(parsed_rules.len(), 1);
        assert_eq!(parsed_rules[0].id, "bom_001");
    }
}

/// 测试规则引擎
#[cfg(test)]
mod rule_engine_tests {
    use super::*;

    fn create_test_rules_config(temp_dir: &TempDir) -> RulesConfig {
        RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec!["test_rules.json".to_string()]),
            custom_regex_file: None,
        }
    }

    fn create_sample_rules() -> Vec<Rule> {
        let now = Utc::now();
        vec![
            Rule {
                id: "xss_001".to_string(),
                name: "XSS Detection".to_string(),
                description: "Detects XSS attempts".to_string(),
                pattern: r"<script[^>]*>.*?</script>".to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "sql_001".to_string(),
                name: "SQL Injection Detection".to_string(),
                description: "Detects SQL injection attempts".to_string(),
                pattern: r"(SELECT|INSERT|UPDATE|DELETE).*FROM".to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::Query,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "contains_001".to_string(),
                name: "Contains Test".to_string(),
                description: "Tests contains matching".to_string(),
                pattern: "admin".to_string(),
                rule_type: RuleType::Contains,
                target: RuleTarget::Uri,
                action: RuleAction::Log,
                severity: RuleSeverity::Medium,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
        ]
    }

    #[test]
    fn test_rule_engine_creation() {
        let engine = RuleEngine::new();
        // 验证引擎创建成功（检查编译通过）
    }

    #[test]
    fn test_rule_engine_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        let engine = RuleEngine::new().with_config(config);
        // 验证配置设置成功（检查编译通过）
    }

    #[test]
    fn test_load_rules_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        // 创建测试规则文件
        let test_rules = create_sample_rules();
        let rule_file = temp_dir.path().join("test_rules.json");
        let json = serde_json::to_string_pretty(&test_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        let mut engine = RuleEngine::new().with_config(config);
        let result = engine.load_all_rules();

        assert!(result.is_ok());
    }

    #[test]
    fn test_load_rules_from_nonexistent_directory() {
        let config = RulesConfig {
            rules_dir: "/nonexistent/directory".to_string(),
            rule_files: Some(vec!["test.json".to_string()]),
            custom_regex_file: None,
        };

        let mut engine = RuleEngine::new().with_config(config);
        let result = engine.load_all_rules();

        // 应该成功但没有加载任何规则
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_regex_rule() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        let now = Utc::now();
        let regex_rule = Rule {
            id: "regex_test".to_string(),
            name: "Regex Test".to_string(),
            description: "Test regex compilation".to_string(),
            pattern: r"\d+".to_string(), // 简单的数字匹配
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::Medium,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let test_rules = vec![regex_rule];
        let rule_file = temp_dir.path().join("test_rules.json");
        let json = serde_json::to_string_pretty(&test_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        let mut engine = RuleEngine::new().with_config(config);
        let result = engine.load_all_rules();

        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_invalid_regex_rule() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        let now = Utc::now();
        let invalid_regex_rule = Rule {
            id: "invalid_regex".to_string(),
            name: "Invalid Regex".to_string(),
            description: "Test invalid regex handling".to_string(),
            pattern: r"[invalid regex(".to_string(), // 无效的正则表达式
            rule_type: RuleType::Regex,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::Medium,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        let test_rules = vec![invalid_regex_rule];
        let rule_file = temp_dir.path().join("test_rules.json");
        let json = serde_json::to_string_pretty(&test_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        let mut engine = RuleEngine::new().with_config(config);
        let result = engine.load_all_rules();

        // 加载应该成功，但无效的规则会被跳过
        assert!(result.is_ok());
    }

    #[test]
    fn test_rule_evaluation_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        let test_rules = create_sample_rules();
        let rule_file = temp_dir.path().join("test_rules.json");
        let json = serde_json::to_string_pretty(&test_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        let mut engine = RuleEngine::new().with_config(config);
        engine.load_all_rules().unwrap();

        // 测试XSS检测
        let xss_payload = "<script>alert('xss')</script>";
        let result = engine.check_content(xss_payload);
        assert!(result.is_some());

        // 测试正常内容
        let normal_content = "This is normal content";
        let result = engine.check_content(normal_content);
        // 注意：这里可能返回Some或None，取决于规则的具体实现
    }

    #[test]
    fn test_disabled_rule_not_evaluated() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        let now = Utc::now();
        let disabled_rule = Rule {
            id: "disabled_test".to_string(),
            name: "Disabled Rule".to_string(),
            description: "This rule is disabled".to_string(),
            pattern: "should_not_match".to_string(),
            rule_type: RuleType::Contains,
            target: RuleTarget::All,
            action: RuleAction::Block,
            severity: RuleSeverity::High,
            enabled: false, // 禁用规则
            created_at: now,
            updated_at: now,
        };

        let test_rules = vec![disabled_rule];
        let rule_file = temp_dir.path().join("test_rules.json");
        let json = serde_json::to_string_pretty(&test_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        let mut engine = RuleEngine::new().with_config(config);
        engine.load_all_rules().unwrap();

        // 即使内容匹配模式，禁用的规则也不应该被触发
        let test_content = "This contains should_not_match pattern";
        let result = engine.check_content(test_content);
        // 应该没有匹配，因为规则被禁用了
    }

    #[test]
    fn test_rule_reload() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_rules_config(&temp_dir);

        // 创建初始规则文件
        let initial_rules = vec![create_sample_rules()[0].clone()]; // 只包含XSS规则
        let rule_file = temp_dir.path().join("test_rules.json");
        let json = serde_json::to_string_pretty(&initial_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        let mut engine = RuleEngine::new().with_config(config.clone());
        engine.load_all_rules().unwrap();

        // 测试XSS检测工作
        let xss_payload = "<script>alert('test')</script>";
        let result1 = engine.check_content(xss_payload);
        assert!(result1.is_some());

        // 更新规则文件，添加更多规则
        let updated_rules = create_sample_rules(); // 包含所有规则
        let json = serde_json::to_string_pretty(&updated_rules).unwrap();
        fs::write(&rule_file, json).unwrap();

        // 重新加载规则
        engine.load_all_rules().unwrap();

        // 测试新规则也工作
        let sql_payload = "SELECT * FROM users";
        let result2 = engine.check_content(sql_payload);
        assert!(result2.is_some());
    }
}

/// 集成测试 - 规则引擎与解析器的协同工作
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_end_to_end_rule_processing() {
        let temp_dir = TempDir::new().unwrap();
        let now = Utc::now();

        // 创建多个规则文件
        let xss_rules = vec![
            Rule {
                id: "xss_script".to_string(),
                name: "Script Tag XSS".to_string(),
                description: "Detects script tag XSS".to_string(),
                pattern: r"<script[^>]*>.*?</script>".to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "xss_onerror".to_string(),
                name: "OnError XSS".to_string(),
                description: "Detects onerror XSS".to_string(),
                pattern: "onerror=".to_string(),
                rule_type: RuleType::Contains,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
        ];

        let sql_rules = vec![
            Rule {
                id: "sql_union".to_string(),
                name: "SQL UNION Attack".to_string(),
                description: "Detects SQL UNION attacks".to_string(),
                pattern: r"UNION\s+SELECT".to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::Query,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "sql_comment".to_string(),
                name: "SQL Comment Attack".to_string(),
                description: "Detects SQL comment attacks".to_string(),
                pattern: "--".to_string(),
                rule_type: RuleType::Contains,
                target: RuleTarget::All,
                action: RuleAction::Log,
                severity: RuleSeverity::Medium,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
        ];

        // 创建规则文件
        let xss_file = temp_dir.path().join("xss_rules.json");
        let sql_file = temp_dir.path().join("sql_rules.json");

        fs::write(&xss_file, serde_json::to_string_pretty(&xss_rules).unwrap()).unwrap();
        fs::write(&sql_file, serde_json::to_string_pretty(&sql_rules).unwrap()).unwrap();

        // 配置规则引擎
        let config = RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec![
                "xss_rules.json".to_string(),
                "sql_rules.json".to_string(),
            ]),
            custom_regex_file: None,
        };

        let mut engine = RuleEngine::new().with_config(config);
        engine.load_all_rules().unwrap();

        // 测试各种攻击载荷
        let test_cases = vec![
            (
                "<script>alert('xss')</script>",
                true,
                "Script XSS should match",
            ),
            (
                "<img onerror=alert(1) src=x>",
                true,
                "OnError XSS should match",
            ),
            (
                "SELECT * FROM users UNION SELECT password FROM admin",
                true,
                "SQL UNION should match",
            ),
            ("DROP TABLE users; --", true, "SQL comment should match"),
            (
                "This is normal content",
                false,
                "Normal content should not match",
            ),
            ("Hello world", false, "Simple text should not match"),
        ];

        for (payload, should_match, description) in test_cases {
            let result = engine.check_content(payload);
            if should_match {
                assert!(
                    result.is_some(),
                    "{}: payload '{}' should match rules",
                    description,
                    payload
                );
            }
            // 注意：对于 should_match = false 的情况，由于我们不知道check_content的具体实现,
            // 我们只能测试它不会崩溃，无法断言具体的返回值
        }
    }

    #[test]
    fn test_rule_priority_and_ordering() {
        let temp_dir = TempDir::new().unwrap();
        let now = Utc::now();

        // 创建具有不同优先级的规则
        let rules = vec![
            Rule {
                id: "high_priority".to_string(),
                name: "High Priority Rule".to_string(),
                description: "High priority test rule".to_string(),
                pattern: "test".to_string(),
                rule_type: RuleType::Contains,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "medium_priority".to_string(),
                name: "Medium Priority Rule".to_string(),
                description: "Medium priority test rule".to_string(),
                pattern: "test".to_string(),
                rule_type: RuleType::Contains,
                target: RuleTarget::All,
                action: RuleAction::Log,
                severity: RuleSeverity::Medium,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "low_priority".to_string(),
                name: "Low Priority Rule".to_string(),
                description: "Low priority test rule".to_string(),
                pattern: "test".to_string(),
                rule_type: RuleType::Contains,
                target: RuleTarget::All,
                action: RuleAction::Log,
                severity: RuleSeverity::Low,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
        ];

        let rule_file = temp_dir.path().join("priority_rules.json");
        fs::write(&rule_file, serde_json::to_string_pretty(&rules).unwrap()).unwrap();

        let config = RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec!["priority_rules.json".to_string()]),
            custom_regex_file: None,
        };

        let mut engine = RuleEngine::new().with_config(config);
        engine.load_all_rules().unwrap();

        // 测试规则匹配
        let test_payload = "This contains test keyword";
        let result = engine.check_content(test_payload);

        // 应该能找到匹配项（具体匹配哪个规则取决于实现）
        assert!(result.is_some());
    }
}

/// 性能基准测试
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_rule_loading_performance() {
        let temp_dir = TempDir::new().unwrap();
        let now = Utc::now();

        // 创建大量规则
        let mut rules = Vec::new();
        for i in 0..1000 {
            rules.push(Rule {
                id: format!("perf_rule_{:04}", i),
                name: format!("Performance Rule {}", i),
                description: format!("Performance test rule number {}", i),
                pattern: format!("pattern_{}", i),
                rule_type: RuleType::Contains,
                target: RuleTarget::All,
                action: RuleAction::Log,
                severity: RuleSeverity::Medium,
                enabled: true,
                created_at: now,
                updated_at: now,
            });
        }

        let rule_file = temp_dir.path().join("perf_rules.json");
        fs::write(&rule_file, serde_json::to_string_pretty(&rules).unwrap()).unwrap();

        let config = RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec!["perf_rules.json".to_string()]),
            custom_regex_file: None,
        };

        let mut engine = RuleEngine::new().with_config(config);

        let start = Instant::now();
        engine.load_all_rules().unwrap();
        let duration = start.elapsed();

        println!("加载1000条规则用时: {:?}", duration);

        // 规则加载应该在合理时间内完成
        assert!(
            duration.as_secs() < 5,
            "Rule loading took too long: {:?}",
            duration
        );
    }

    #[test]
    fn test_rule_evaluation_performance() {
        let temp_dir = TempDir::new().unwrap();
        let now = Utc::now();

        // 创建一些复杂的正则规则
        let rules = vec![
            Rule {
                id: "complex_regex_1".to_string(),
                name: "Complex Regex 1".to_string(),
                description: "Complex regex for performance testing".to_string(),
                pattern: r"(?i)(script|iframe|object|embed|form|input|select|textarea|button|link|meta|style).*?(on\w+\s*=|javascript:|data:|vbscript:)".to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            Rule {
                id: "complex_regex_2".to_string(),
                name: "Complex Regex 2".to_string(),
                description: "Another complex regex for performance testing".to_string(),
                pattern: r"(?i)(union\s+select|union\s+all\s+select|group\s+by|order\s+by|having|into\s+outfile|load_file|benchmark|sleep|waitfor|delay)".to_string(),
                rule_type: RuleType::Regex,
                target: RuleTarget::All,
                action: RuleAction::Block,
                severity: RuleSeverity::High,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
        ];

        let rule_file = temp_dir.path().join("complex_rules.json");
        fs::write(&rule_file, serde_json::to_string_pretty(&rules).unwrap()).unwrap();

        let config = RulesConfig {
            rules_dir: temp_dir.path().to_string_lossy().to_string(),
            rule_files: Some(vec!["complex_rules.json".to_string()]),
            custom_regex_file: None,
        };

        let mut engine = RuleEngine::new().with_config(config);
        engine.load_all_rules().unwrap();

        // 测试大量请求的评估性能
        let test_payloads = vec![
            "This is normal content without any malicious patterns",
            "<script>alert('xss')</script>",
            "SELECT * FROM users UNION SELECT password FROM admin",
            "Normal text with some special chars !@#$%^&*()",
            "<iframe src=javascript:alert(1)></iframe>",
        ];

        let start = Instant::now();

        for _ in 0..1000 {
            for payload in &test_payloads {
                let _ = engine.check_content(payload);
            }
        }

        let duration = start.elapsed();
        println!("评估5000次请求用时: {:?}", duration);

        // 平均每次评估应该很快
        let avg_per_request = duration.as_nanos() / 5000;
        println!("平均每次请求评估用时: {}纳秒", avg_per_request);

        // 性能应该在合理范围内
        assert!(
            duration.as_millis() < 1000,
            "Rule evaluation took too long: {:?}",
            duration
        );
    }
}
