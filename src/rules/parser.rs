//! 规则解析器模块，用于解析和缓存规则文件

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::core::cache_manager::CacheManager;
use crate::rules::model::Rule;

/// 规则文件元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFileMeta {
    /// 文件路径
    pub path: String,
    /// 最后修改时间
    pub last_modified: u64,
    /// 文件大小
    pub size: u64,
    /// 规则数量
    pub rule_count: usize,
}

/// 规则解析器
pub struct RuleParser {
    /// 规则目录
    rules_dir: PathBuf,
    /// 是否使用缓存
    use_cache: bool,
    /// 缓存键前缀
    cache_prefix: String,
}

impl RuleParser {
    /// 创建新的规则解析器
    pub fn new<P: AsRef<Path>>(rules_dir: P, use_cache: bool) -> Self {
        Self {
            rules_dir: rules_dir.as_ref().to_path_buf(),
            use_cache,
            cache_prefix: "rule_file:".to_string(),
        }
    }

    /// 解析规则文件
    pub fn parse_rule_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Rule>> {
        let path = path.as_ref();
        let cache_key = format!("{}{}", self.cache_prefix, path.display());

        // 获取文件元数据
        let metadata = path
            .metadata()
            .context(format!("无法获取规则文件元数据: {path:?}"))?;

        // 获取文件最后修改时间
        let last_modified = metadata
            .modified()
            .context(format!("无法获取规则文件修改时间: {path:?}"))?
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 获取文件大小
        let size = metadata.len();

        // 如果启用了缓存，尝试从缓存获取
        if self.use_cache {
            if let Some(cache) = CacheManager::global()
                .get_file_cache::<String, (RuleFileMeta, Vec<Rule>)>("default")
            {
                if let Some((meta, rules)) = cache.get(&cache_key) {
                    // 检查文件是否已更改
                    if meta.last_modified == last_modified && meta.size == size {
                        debug!("从缓存加载规则文件: {:?}, 规则数量: {}", path, rules.len());
                        return Ok(rules);
                    }
                }
            }
        }

        // 从文件加载规则
        let file = File::open(path).context(format!("无法打开规则文件: {path:?}"))?;
        let reader = BufReader::new(file);

        // 使用带有BOM处理能力的方法解析JSON
        let rules: Vec<Rule> = match serde_json::from_reader(reader) {
            Ok(rules) => rules,
            Err(_e) => {
                // 如果解析失败，尝试读取文件内容并处理可能的BOM
                let mut content = std::fs::read_to_string(path)
                    .context(format!("无法读取规则文件内容: {path:?}"))?;

                // 移除UTF-8 BOM标记（如果存在）
                if content.starts_with('\u{feff}') {
                    content = content[3..].to_string();
                    warn!("检测到并移除了UTF-8 BOM标记: {:?}", path);
                }

                serde_json::from_str(&content)
                    .context(format!("无法解析规则文件（尝试移除BOM后）: {path:?}"))?
            }
        };

        info!("从文件加载规则: {:?}, 规则数量: {}", path, rules.len());

        // 如果启用了缓存，将规则存入缓存
        if self.use_cache {
            let meta = RuleFileMeta {
                path: path.to_string_lossy().to_string(),
                last_modified,
                size,
                rule_count: rules.len(),
            };

            if let Some(cache) = CacheManager::global()
                .get_file_cache::<String, (RuleFileMeta, Vec<Rule>)>("default")
            {
                cache.insert(cache_key, (meta, rules.clone()));
                debug!("规则文件已缓存: {:?}", path);
            }
        }

        Ok(rules)
    }

    /// 解析目录中的所有规则文件
    pub fn parse_all_rules(&self) -> Result<Vec<Rule>> {
        let mut all_rules = Vec::new();
        let mut json_files = Vec::new();

        // 检查规则目录是否存在
        if !self.rules_dir.exists() || !self.rules_dir.is_dir() {
            warn!("规则目录不存在: {:?}", self.rules_dir);
            return Ok(all_rules);
        }

        // 收集目录中所有.json文件
        if let Ok(entries) = std::fs::read_dir(&self.rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "json") {
                    json_files.push(path);
                }
            }
        }

        // 按文件名排序，确保加载顺序一致
        json_files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        // 优先加载非default.json的文件
        let mut default_json: Option<PathBuf> = None;

        for path in json_files {
            if path.file_name().is_some_and(|name| name == "default.json") {
                default_json = Some(path);
                continue;
            }

            match self.parse_rule_file(&path) {
                Ok(rules) => {
                    info!("成功加载规则文件: {:?}, 规则数量: {}", path, rules.len());
                    all_rules.extend(rules);
                }
                Err(err) => {
                    error!("解析规则文件失败 {:?}: {}", path, err);
                }
            }
        }

        // 最后加载default.json
        if let Some(path) = default_json {
            match self.parse_rule_file(&path) {
                Ok(rules) => {
                    info!(
                        "成功加载默认规则文件: {:?}, 规则数量: {}",
                        path,
                        rules.len()
                    );
                    all_rules.extend(rules);
                }
                Err(err) => {
                    error!("解析默认规则文件失败 {:?}: {}", path, err);
                }
            }
        }

        info!("总共解析了 {} 条规则", all_rules.len());
        Ok(all_rules)
    }

    /// 解析指定的规则文件列表
    pub fn parse_rule_files(&self, file_names: &[String]) -> Result<Vec<Rule>> {
        let mut all_rules = Vec::new();

        for file_name in file_names {
            let file_path = self.rules_dir.join(file_name);
            if file_path.exists() && file_path.is_file() {
                match self.parse_rule_file(&file_path) {
                    Ok(rules) => {
                        all_rules.extend(rules);
                    }
                    Err(err) => {
                        error!("解析规则文件失败 {:?}: {}", file_path, err);
                    }
                }
            } else {
                warn!("规则文件不存在: {:?}", file_path);
            }
        }

        info!("从指定文件列表解析了 {} 条规则", all_rules.len());
        Ok(all_rules)
    }

    /// 清除规则缓存
    #[allow(dead_code)]
    pub fn clear_cache(&self) -> io::Result<()> {
        if self.use_cache {
            if let Some(cache) = CacheManager::global()
                .get_file_cache::<String, (RuleFileMeta, Vec<Rule>)>("default")
            {
                // 清除所有缓存项
                cache.clear();
                info!("已清除规则缓存");
            }
        }
        Ok(())
    }
}
