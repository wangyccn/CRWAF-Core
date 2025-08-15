use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 规则类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum RuleType {
    /// 正则表达式规则
    Regex,
    /// 精确匹配规则
    Exact,
    /// 包含匹配规则
    Contains,
    /// 前缀匹配规则
    StartsWith,
    /// 后缀匹配规则
    EndsWith,
}

/// 规则目标
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum RuleTarget {
    /// URI路径
    Uri,
    /// 请求头
    Header,
    /// 请求体
    Body,
    /// 查询参数
    Query,
    /// Cookie
    Cookie,
    /// 所有内容
    All,
}

/// 规则动作
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum RuleAction {
    /// 阻止请求
    Block,
    /// 记录但允许请求
    Log,
    /// 重定向请求
    Redirect,
    /// 验证码挑战
    Captcha,
}

/// 攻击类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackType {
    /// 跨站脚本攻击
    XSS,
    /// SQL注入攻击
    SQLInjection,
    /// 服务器端请求伪造
    SSRF,
    /// WebShell攻击
    WebShell,
    /// 自定义规则匹配
    Custom,
}

/// 检测级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DetectionLevel {
    /// 低级别检测
    Low,
    /// 中级别检测
    Medium,
    /// 高级别检测
    High,
}

/// 攻击信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackInfo {
    /// 攻击类型
    pub attack_type: AttackType,
    /// 攻击描述
    pub description: String,
    /// 置信度 (0.0 - 1.0)
    pub confidence: f64,
    /// 严重程度
    pub severity: DetectionLevel,
    /// 匹配的规则ID
    pub matched_rule: Option<String>,
    /// 额外详情
    pub details: HashMap<String, String>,
}

/// 规则严重性
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum RuleSeverity {
    /// 低风险
    Low,
    /// 中风险
    Medium,
    /// 高风险
    High,
    /// 严重风险
    Critical,
}

/// WAF规则定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// 规则ID
    pub id: String,
    /// 规则名称
    pub name: String,
    /// 规则描述
    pub description: String,
    /// 匹配模式
    pub pattern: Box<str>,
    /// 规则类型
    pub rule_type: RuleType,
    /// 规则目标
    pub target: RuleTarget,
    /// 规则动作
    pub action: RuleAction,
    /// 规则严重性
    pub severity: RuleSeverity,
    /// 是否启用
    pub enabled: bool,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}
