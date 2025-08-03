use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

/// 规则严重性
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    pub pattern: String,
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