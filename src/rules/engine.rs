use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use regex::Regex;
use tracing::{error, info, warn};

use crate::core::config::RulesConfig;
use crate::rules::model::{Rule, RuleType};
use crate::rules::parser::RuleParser;

/// 规则引擎
pub struct RuleEngine {
    /// 已编译的规则列表
    rules: Vec<Arc<CompiledRule>>,
    /// 规则配置
    config: Option<RulesConfig>,
}

/// 已编译的规则
#[derive(Debug)]
pub struct CompiledRule {
    /// 原始规则
    #[allow(dead_code)]
    pub rule: Rule,
    /// 编译后的正则表达式（如果是正则规则）
    #[allow(dead_code)]
    pub regex: Option<Regex>,
}

impl RuleEngine {
    /// 创建新的规则引擎
    pub fn new() -> Self {
        Self { 
            rules: Vec::new(),
            config: None,
        }
    }
    
    /// 设置规则配置
    pub fn with_config(mut self, config: RulesConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// 从文件加载规则（不使用缓存）
    fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(&path).context(format!("无法打开规则文件: {:?}", path.as_ref()))?;
        let reader = BufReader::new(file);

        let rules: Vec<Rule> = serde_json::from_reader(reader)
            .context(format!("无法解析规则文件: {:?}", path.as_ref()))?;

        info!("从 {:?} 加载了 {} 条规则", path.as_ref(), rules.len());

        // 编译规则
        for rule in rules {
            match self.compile_rule(rule) {
                Ok(compiled_rule) => {
                    self.rules.push(Arc::new(compiled_rule));
                }
                Err(e) => {
                    error!("编译规则失败: {}", e);
                }
            }
        }

        info!("成功编译 {} 条规则", self.rules.len());
        Ok(())
    }
    
    /// 加载所有规则文件
    pub fn load_all_rules(&mut self) -> Result<()> {
        // 清空现有规则
        self.rules.clear();
        
        if let Some(config) = &self.config {
            let rules_dir = Path::new(&config.rules_dir);
            
            // 检查规则目录是否存在
            if !rules_dir.exists() || !rules_dir.is_dir() {
                warn!("规则目录不存在: {:?}", rules_dir);
                return Ok(());
            }
            
            // 创建规则解析器，启用缓存
            let parser = RuleParser::new(rules_dir, true);
            
            let rules = if let Some(rule_files) = &config.rule_files {
                // 如果指定了规则文件列表，则按照列表顺序加载
                parser.parse_rule_files(rule_files)?
            } else {
                // 否则加载目录下所有.json文件
                parser.parse_all_rules()?
            };
            
            // 编译规则
            for rule in rules {
                match self.compile_rule(rule) {
                    Ok(compiled_rule) => {
                        self.rules.push(Arc::new(compiled_rule));
                    }
                    Err(e) => {
                        error!("编译规则失败: {}", e);
                    }
                }
            }
        } else {
            // 如果没有配置，则加载默认规则文件
            let default_path = Path::new("rules/default.json");
            if default_path.exists() {
                self.load_from_file(default_path)?;
            } else {
                warn!("默认规则文件不存在: {:?}", default_path);
            }
        }
        
        info!("总共加载了 {} 条规则", self.rules.len());
        Ok(())
    }
    


    /// 编译单个规则
    fn compile_rule(&self, rule: Rule) -> Result<CompiledRule> {
        let regex = if rule.rule_type == RuleType::Regex {
            // 编译正则表达式
            Some(Regex::new(&rule.pattern).context("无法编译正则表达式规则")?)
        } else {
            None
        };

        Ok(CompiledRule { rule, regex })
    }

    /// 获取所有规则
    #[allow(dead_code)]
    pub fn get_rules(&self) -> &[Arc<CompiledRule>] {
        &self.rules
    }

    /// 获取启用的规则
    #[allow(dead_code)]
    pub fn get_enabled_rules(&self) -> Vec<Arc<CompiledRule>> {
        self.rules
            .iter()
            .filter(|r| r.rule.enabled)
            .cloned()
            .collect()
    }

    /// 匹配内容是否符合规则
    #[allow(dead_code)]
    pub fn matches(&self, content: &str, rule: &CompiledRule) -> bool {
        match rule.rule.rule_type {
            RuleType::Regex => {
                if let Some(regex) = &rule.regex {
                    regex.is_match(content)
                } else {
                    false
                }
            }
            RuleType::Exact => content == rule.rule.pattern,
            RuleType::Contains => content.contains(&rule.rule.pattern),
            RuleType::StartsWith => content.starts_with(&rule.rule.pattern),
            RuleType::EndsWith => content.ends_with(&rule.rule.pattern),
        }
    }

    /// 检查内容是否匹配任何规则
    #[allow(dead_code)]
    pub fn check_content(&self, content: &str) -> Option<Arc<CompiledRule>> {
        for rule in &self.rules {
            if rule.rule.enabled && self.matches(content, rule) {
                return Some(rule.clone());
            }
        }
        None
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

// 规则文件优先级：
// 1. 配置文件中指定的规则文件列表，按照列表顺序
// 2. 如果没有指定规则文件列表，则加载目录下所有.json文件，非default.json的文件优先级高于default.json