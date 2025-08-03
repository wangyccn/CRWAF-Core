use anyhow::Result;
use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tracing::{info, warn};

#[cfg(feature = "compression")]
use flate2::{write::GzEncoder, Compression};

/// 日志类型
#[derive(Clone, Copy, Debug)]
pub enum LogType {
    Access,
    Attack,
    System,
}

impl LogType {
    fn as_str(&self) -> &'static str {
        match self {
            LogType::Access => "access",
            LogType::Attack => "attack",
            LogType::System => "system",
        }
    }
}

/// 日志轮转策略
#[derive(Clone, Debug)]
pub enum RotationPolicy {
    /// 按大小轮转（字节）
    Size(u64),
    /// 按时间轮转（小时）
    Time(u64),
    /// 不自动轮转
    Never,
}

/// 日志压缩策略
#[derive(Clone, Copy, Debug)]
pub enum CompressionPolicy {
    /// 不压缩
    None,
    /// Gzip压缩
    #[cfg(feature = "compression")]
    Gzip,
}

/// 日志配置
#[derive(Clone, Debug)]
pub struct LogConfig {
    /// 日志目录
    pub log_dir: String,
    /// 日志文件前缀
    pub prefix: String,
    /// 轮转策略
    pub rotation_policy: RotationPolicy,
    /// 压缩策略
    pub compression_policy: CompressionPolicy,
    /// 保留日志文件数量
    pub max_files: Option<usize>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: "logs".to_string(),
            prefix: "crwaf".to_string(),
            rotation_policy: RotationPolicy::Time(24), // 默认24小时轮转一次
            compression_policy: CompressionPolicy::None,
            max_files: Some(30), // 默认保留30个日志文件
        }
    }
}

/// 日志文件信息
#[derive(Debug)]
struct LogFile {
    /// 文件句柄
    file: File,
    /// 文件路径
    path: PathBuf,
    /// 创建时间
    #[allow(dead_code)]
    created_at: SystemTime,
    /// 当前大小
    size: u64,
}

/// 文件日志记录器
#[derive(Debug)]
pub struct FileLogger {
    /// 日志配置
    config: LogConfig,
    /// 访问日志
    access_log: Mutex<Option<LogFile>>,
    /// 攻击日志
    attack_log: Mutex<Option<LogFile>>,
    /// 系统日志
    system_log: Mutex<Option<LogFile>>,
    /// 上次轮转时间
    last_rotation: Mutex<SystemTime>,
}

impl FileLogger {
    /// 创建新的日志记录器
    #[allow(dead_code)]
    pub fn new(config: LogConfig) -> Result<Self> {
        // 确保日志目录存在
        fs::create_dir_all(&config.log_dir)?;

        let logger = Self {
            config,
            access_log: Mutex::new(None),
            attack_log: Mutex::new(None),
            system_log: Mutex::new(None),
            last_rotation: Mutex::new(SystemTime::now()),
        };

        // 初始化日志文件
        logger.init_log_file(LogType::Access)?;
        logger.init_log_file(LogType::Attack)?;
        logger.init_log_file(LogType::System)?;

        // 清理旧日志文件
        logger.cleanup_old_logs()?;

        Ok(logger)
    }

    /// 使用默认配置创建日志记录器
    #[allow(dead_code)]
    pub fn with_default_config(log_dir: &str) -> Result<Self> {
        let config = LogConfig {
            log_dir: log_dir.to_string(),
            ..Default::default()
        };
        Self::new(config)
    }

    /// 初始化日志文件
    #[allow(dead_code)]
    fn init_log_file(&self, log_type: LogType) -> Result<()> {
        let date = Local::now().format("%Y-%m-%d").to_string();
        let file_name = format!("{}-{}-{}.log", self.config.prefix, log_type.as_str(), date);
        let file_path = PathBuf::from(&self.config.log_dir).join(&file_name);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        // 获取文件大小
        let metadata = file.metadata()?;
        let size = metadata.len();

        // 创建日志文件信息
        let log_file = LogFile {
            file,
            path: file_path.clone(),
            created_at: SystemTime::now(),
            size,
        };

        // 更新对应的日志文件
        match log_type {
            LogType::Access => {
                let mut access_log = self.access_log.lock().unwrap();
                *access_log = Some(log_file);
            }
            LogType::Attack => {
                let mut attack_log = self.attack_log.lock().unwrap();
                *attack_log = Some(log_file);
            }
            LogType::System => {
                let mut system_log = self.system_log.lock().unwrap();
                *system_log = Some(log_file);
            }
        }

        info!(
            "Initialized {} log file: {}",
            log_type.as_str(),
            file_path.display()
        );
        Ok(())
    }
    /// 写入日志
    #[allow(dead_code)]
    pub fn log(&self, log_type: LogType, message: &str) -> Result<()> {
        // 检查是否需要轮转
        self.check_rotation()?;

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let log_entry = format!("[{timestamp}] {message}\n");
        let entry_bytes = log_entry.as_bytes();

        match log_type {
            LogType::Access => {
                let mut access_log = self.access_log.lock().unwrap();
                if let Some(log_file) = access_log.as_mut() {
                    log_file.file.write_all(entry_bytes)?;
                    log_file.file.flush()?;
                    log_file.size += entry_bytes.len() as u64;

                    // 检查是否需要按大小轮转
                    if let RotationPolicy::Size(max_size) = self.config.rotation_policy {
                        if log_file.size >= max_size {
                            drop(access_log); // 释放锁
                            self.rotate_log(LogType::Access)?;
                        }
                    }
                } else {
                    warn!("Access log file not initialized");
                    self.init_log_file(LogType::Access)?;
                }
            }
            LogType::Attack => {
                let mut attack_log = self.attack_log.lock().unwrap();
                if let Some(log_file) = attack_log.as_mut() {
                    log_file.file.write_all(entry_bytes)?;
                    log_file.file.flush()?;
                    log_file.size += entry_bytes.len() as u64;

                    // 检查是否需要按大小轮转
                    if let RotationPolicy::Size(max_size) = self.config.rotation_policy {
                        if log_file.size >= max_size {
                            drop(attack_log); // 释放锁
                            self.rotate_log(LogType::Attack)?;
                        }
                    }
                } else {
                    warn!("Attack log file not initialized");
                    self.init_log_file(LogType::Attack)?;
                }
            }
            LogType::System => {
                let mut system_log = self.system_log.lock().unwrap();
                if let Some(log_file) = system_log.as_mut() {
                    log_file.file.write_all(entry_bytes)?;
                    log_file.file.flush()?;
                    log_file.size += entry_bytes.len() as u64;

                    // 检查是否需要按大小轮转
                    if let RotationPolicy::Size(max_size) = self.config.rotation_policy {
                        if log_file.size >= max_size {
                            drop(system_log); // 释放锁
                            self.rotate_log(LogType::System)?;
                        }
                    }
                } else {
                    warn!("System log file not initialized");
                    self.init_log_file(LogType::System)?;
                }
            }
        }

        Ok(())
    }

    /// 记录访问日志
    #[allow(dead_code)]
    pub fn access(&self, message: &str) -> Result<()> {
        self.log(LogType::Access, message)
    }

    /// 记录攻击日志
    #[allow(dead_code)]
    pub fn attack(&self, message: &str) -> Result<()> {
        self.log(LogType::Attack, message)
    }

    /// 记录系统日志
    #[allow(dead_code)]
    pub fn system(&self, message: &str) -> Result<()> {
        self.log(LogType::System, message)
    }

    /// 手动轮转所有日志文件
    #[allow(dead_code)]
    pub fn rotate(&self) -> Result<()> {
        self.rotate_all()
    }

    /// 获取日志配置
    #[allow(dead_code)]
    pub fn get_config(&self) -> &LogConfig {
        &self.config
    }

    /// 更新日志配置
    #[allow(dead_code)]
    pub fn update_config(&mut self, config: LogConfig) -> Result<()> {
        // 如果日志目录发生变化，需要确保新目录存在
        if self.config.log_dir != config.log_dir {
            fs::create_dir_all(&config.log_dir)?;
        }

        // 更新配置
        self.config = config;

        // 轮转日志文件以应用新配置
        self.rotate_all()
    }

    /// 检查是否需要按时间轮转日志
    fn check_rotation(&self) -> Result<()> {
        // 如果不是按时间轮转，直接返回
        if !matches!(self.config.rotation_policy, RotationPolicy::Time(_)) {
            return Ok(());
        }

        let now = SystemTime::now();
        let mut last_rotation = self.last_rotation.lock().unwrap();

        // 计算距离上次轮转的时间（小时）
        let duration = now
            .duration_since(*last_rotation)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs()
            / 3600; // 转换为小时

        // 检查是否需要轮转
        if let RotationPolicy::Time(hours) = self.config.rotation_policy {
            if duration >= hours {
                // 更新上次轮转时间
                *last_rotation = now;
                drop(last_rotation); // 释放锁

                // 轮转所有日志文件
                self.rotate_all()?;
            }
        }

        Ok(())
    }

    /// 轮转所有日志文件
    fn rotate_all(&self) -> Result<()> {
        // 轮转各类日志文件
        self.rotate_log(LogType::Access)?;
        self.rotate_log(LogType::Attack)?;
        self.rotate_log(LogType::System)?;

        // 清理旧日志文件
        self.cleanup_old_logs()?;

        info!("Rotated all log files");
        Ok(())
    }

    /// 轮转指定类型的日志文件
    fn rotate_log(&self, log_type: LogType) -> Result<()> {
        let mut log_file_guard = match log_type {
            LogType::Access => self.access_log.lock().unwrap(),
            LogType::Attack => self.attack_log.lock().unwrap(),
            LogType::System => self.system_log.lock().unwrap(),
        };

        // 如果日志文件不存在，直接初始化
        if log_file_guard.is_none() {
            drop(log_file_guard); // 释放锁
            return self.init_log_file(log_type);
        }

        // 获取旧日志文件信息
        let old_log_file = log_file_guard.take().unwrap();
        let old_path = old_log_file.path.clone();

        // 关闭旧日志文件（通过drop）
        drop(old_log_file);

        // 初始化新日志文件
        drop(log_file_guard); // 释放锁
        self.init_log_file(log_type)?;

        // 压缩旧日志文件
        match self.config.compression_policy {
            #[cfg(feature = "compression")]
            CompressionPolicy::Gzip => {
                self.compress_log_file(&old_path)?;
            }
            _ => {} // 不压缩
        }

        info!("Rotated {} log file", log_type.as_str());
        Ok(())
    }

    /// 压缩日志文件
    #[cfg(feature = "compression")]
    fn compress_log_file(&self, log_path: &Path) -> Result<()> {
        let gz_path = format!("{}.gz", log_path.display());

        // 打开源文件
        let mut input_file = File::open(log_path)?;
        let mut input_data = Vec::new();
        input_file.read_to_end(&mut input_data)?;
        drop(input_file); // 关闭源文件

        // 创建压缩文件
        let output_file = File::create(&gz_path)?;
        let mut encoder = GzEncoder::new(output_file, Compression::default());
        encoder.write_all(&input_data)?;
        encoder.finish()?;

        // 删除原始文件
        fs::remove_file(log_path)?;

        info!("Compressed log file: {}", gz_path);
        Ok(())
    }

    /// 清理旧日志文件
    fn cleanup_old_logs(&self) -> Result<()> {
        // 如果没有设置最大文件数，不进行清理
        let Some(max_files) = self.config.max_files else {
            return Ok(());
        };

        // 如果最大文件数为0，不进行清理
        if max_files == 0 {
            return Ok(());
        }

        // 获取日志目录中的所有文件
        let log_dir = Path::new(&self.config.log_dir);
        let prefix = &self.config.prefix;

        // 确保目录存在
        if !log_dir.exists() {
            return Ok(());
        }

        // 收集所有日志文件
        let mut log_files = Vec::new();
        for entry in fs::read_dir(log_dir)? {
            let entry = entry?;
            let path = entry.path();

            // 只处理文件
            if !path.is_file() {
                continue;
            }

            // 检查是否是日志文件（以前缀开头）
            if let Some(file_name) = path.file_name() {
                let file_name = file_name.to_string_lossy();
                if file_name.starts_with(prefix) {
                    // 获取文件修改时间
                    if let Ok(metadata) = fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            log_files.push((path, modified));
                        }
                    }
                }
            }
        }

        // 按修改时间排序（最旧的在前）
        log_files.sort_by(|a, b| a.1.cmp(&b.1));

        // 删除超出数量限制的旧文件
        if log_files.len() > max_files {
            for (path, _) in log_files.iter().take(log_files.len() - max_files) {
                if let Err(e) = fs::remove_file(path) {
                    warn!("Failed to remove old log file {}: {}", path.display(), e);
                } else {
                    info!("Removed old log file: {}", path.display());
                }
            }
        }

        Ok(())
    }
}
