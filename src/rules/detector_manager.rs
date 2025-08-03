use std::sync::{Arc, Mutex, OnceLock};

use crate::rules::detector::{AttackDetector, DetectionLevel};

/// 攻击检测器管理器
pub struct DetectorManager {
    detector: Option<Arc<Mutex<AttackDetector>>>,
}

impl DetectorManager {
    /// 获取全局单例实例
    pub fn global() -> &'static Mutex<Self> {
        static INSTANCE: OnceLock<Mutex<DetectorManager>> = OnceLock::new();
        INSTANCE.get_or_init(|| Mutex::new(DetectorManager::new()))
    }

    /// 创建新的检测器管理器
    fn new() -> Self {
        Self { detector: None }
    }

    /// 设置攻击检测器
    pub fn set_detector(&mut self, detector: Arc<Mutex<AttackDetector>>) {
        self.detector = Some(detector);
    }

    /// 获取攻击检测器
    pub fn get_detector(&self) -> Option<Arc<Mutex<AttackDetector>>> {
        self.detector.clone()
    }

    /// 更新检测级别
    pub fn update_detection_level(&mut self, level: DetectionLevel) -> Result<(), String> {
        if let Some(detector) = &self.detector {
            match detector.lock() {
                Ok(mut detector_guard) => {
                    detector_guard.set_level(level);
                    Ok(())
                },
                Err(_) => Err("获取检测器锁失败".to_string())
            }
        } else {
            Err("检测器未初始化".to_string())
        }
    }
}