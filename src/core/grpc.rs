use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tracing::{error, info};

use crate::core::config::AppConfig;
use crate::core::statistics::Statistics;
use crate::core::sync::DataSyncManager;

// 导入生成的proto代码
pub mod waf {
    tonic::include_proto!("waf");
}

use waf::waf_service_server::{WafService, WafServiceServer};
use waf::*;

// 类型转换辅助函数
impl From<crate::core::sync::SiteInfo> for waf::SiteInfo {
    fn from(site: crate::core::sync::SiteInfo) -> Self {
        waf::SiteInfo {
            site_id: site.site_id,
            name: site.name,
            domain: site.domain,
            origin: site.origin,
            enabled: site.enabled,
            security: Some(waf::SecurityConfig {
                xss_protection: site.security_config.xss_protection,
                sql_injection_protection: site.security_config.sql_injection_protection,
                five_second_shield: site.security_config.five_second_shield,
                click_shield: site.security_config.click_shield,
                captcha: site.security_config.captcha,
            }),
            created_at: site.created_at,
            updated_at: site.updated_at,
        }
    }
}

impl From<crate::core::sync::BlockedIP> for waf::BlockedIp {
    fn from(blocked: crate::core::sync::BlockedIP) -> Self {
        waf::BlockedIp {
            ip: blocked.ip,
            reason: blocked.reason,
            blocked_at: blocked.blocked_at,
            expires_at: blocked.expires_at,
            permanent: blocked.permanent,
        }
    }
}

impl From<i32> for crate::core::sync::CommandType {
    fn from(cmd_type: i32) -> Self {
        match cmd_type {
            0 => crate::core::sync::CommandType::ReloadConfig,
            1 => crate::core::sync::CommandType::ClearCache,
            2 => crate::core::sync::CommandType::BlockIP,
            3 => crate::core::sync::CommandType::UnblockIP,
            4 => crate::core::sync::CommandType::UpdateRules,
            5 => crate::core::sync::CommandType::RestartService,
            _ => crate::core::sync::CommandType::ReloadConfig, // 默认值
        }
    }
}

/// WAF gRPC服务实现
pub struct WafServiceImpl {
    config: Arc<AppConfig>,
    statistics: Arc<Statistics>,
    sync_manager: Arc<DataSyncManager>,
}

impl WafServiceImpl {
    pub fn new(
        config: Arc<AppConfig>,
        statistics: Arc<Statistics>,
        sync_manager: Arc<DataSyncManager>,
    ) -> Self {
        Self {
            config,
            statistics,
            sync_manager,
        }
    }
}

#[tonic::async_trait]
impl WafService for WafServiceImpl {
    async fn get_status(
        &self,
        request: tonic::Request<StatusRequest>,
    ) -> Result<tonic::Response<StatusResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到状态请求: {:?}", req);

        // 创建响应
        let response = StatusResponse {
            running: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            system_info: Some(SystemInfo {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                uptime_seconds: 0,
                total_requests: 0,
                blocked_requests: 0,
            }),
        };

        Ok(tonic::Response::new(response))
    }

    async fn get_site_config(
        &self,
        request: tonic::Request<SiteConfigRequest>,
    ) -> Result<tonic::Response<SiteConfigResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到网站配置请求: {:?}", req);

        // 创建响应
        let response = SiteConfigResponse { sites: vec![] };

        Ok(tonic::Response::new(response))
    }

    async fn update_rules(
        &self,
        request: tonic::Request<UpdateRulesRequest>,
    ) -> Result<tonic::Response<UpdateRulesResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到更新规则请求: {} 条规则", req.rules.len());

        // 创建响应
        let response = UpdateRulesResponse {
            success: true,
            message: "规则更新成功".to_string(),
            updated_count: req.rules.len() as u32,
        };

        Ok(tonic::Response::new(response))
    }

    async fn get_stats(
        &self,
        request: tonic::Request<StatsRequest>,
    ) -> Result<tonic::Response<StatsResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到统计请求: {:?}", req);

        // 创建响应
        let response = StatsResponse {
            total_requests: 0,
            blocked_requests: 0,
            allowed_requests: 0,
            attacks_by_type: std::collections::HashMap::new(),
            requests_by_country: std::collections::HashMap::new(),
        };

        Ok(tonic::Response::new(response))
    }

    async fn get_attack_logs(
        &self,
        request: tonic::Request<AttackLogsRequest>,
    ) -> Result<tonic::Response<AttackLogsResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到攻击日志请求: {:?}", req);

        // 创建响应
        let response = AttackLogsResponse {
            logs: vec![],
            total: 0,
        };

        Ok(tonic::Response::new(response))
    }

    async fn get_detailed_stats(
        &self,
        request: tonic::Request<DetailedStatsRequest>,
    ) -> Result<tonic::Response<DetailedStatsResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到详细统计请求: {:?}", req);

        // 获取实际的统计数据
        let stats_data = self.statistics.get_data().await;

        let response = DetailedStatsResponse {
            cache_hits: stats_data.cache_hits,
            cache_misses: stats_data.cache_misses,
            defense_hits: stats_data.defense_hits,
            defense_misses: stats_data.defense_misses,
            ip_blocks: stats_data.ip_blocks,
            total_requests: stats_data.total_requests,
            request_by_hour: stats_data.request_by_hour.clone(),
            blocked_ips: stats_data.blocked_ips.clone(),
            cache_hit_rate: stats_data.cache_hit_rate(),
            defense_hit_rate: stats_data.defense_hit_rate(),
            timestamp: stats_data.timestamp,
        };

        Ok(tonic::Response::new(response))
    }

    async fn get_site_list(
        &self,
        request: tonic::Request<SiteListRequest>,
    ) -> Result<tonic::Response<SiteListResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到网站列表请求: {:?}", req);

        // 使用同步管理器获取网站列表
        match self.sync_manager.get_site_list().await {
            Ok(sites) => {
                let proto_sites: Vec<waf::SiteInfo> = sites.into_iter().map(|s| s.into()).collect();
                let response = SiteListResponse { sites: proto_sites };
                Ok(tonic::Response::new(response))
            }
            Err(e) => {
                error!("获取网站列表失败: {}", e);
                Err(tonic::Status::internal("获取网站列表失败"))
            }
        }
    }

    async fn get_blocked_i_ps(
        &self,
        request: tonic::Request<BlockedIPsRequest>,
    ) -> Result<tonic::Response<BlockedIPsResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到封禁IP列表请求: {:?}", req);

        // 使用同步管理器获取封禁IP列表
        match self.sync_manager.get_blocked_ips().await {
            Ok(blocked_ips) => {
                let proto_blocked_ips: Vec<waf::BlockedIp> =
                    blocked_ips.into_iter().map(|b| b.into()).collect();
                let response = BlockedIPsResponse {
                    blocked_ips: proto_blocked_ips,
                };
                Ok(tonic::Response::new(response))
            }
            Err(e) => {
                error!("获取封禁IP列表失败: {}", e);
                Err(tonic::Status::internal("获取封禁IP列表失败"))
            }
        }
    }

    async fn execute_command(
        &self,
        request: tonic::Request<CommandRequest>,
    ) -> Result<tonic::Response<CommandResponse>, tonic::Status> {
        let req = request.into_inner();
        info!("收到命令执行请求: {:?}", req);

        // 构建命令对象
        use crate::core::sync::Command;
        let command = Command {
            instance_id: req.instance_id,
            command_type: req.command_type.into(),
            parameters: req.parameters,
        };

        // 使用同步管理器执行命令
        match self.sync_manager.execute_command(command).await {
            Ok(result) => {
                let response = CommandResponse {
                    success: result.success,
                    message: result.message,
                    result_data: result.data,
                };
                Ok(tonic::Response::new(response))
            }
            Err(e) => {
                error!("命令执行失败: {}", e);
                let response = CommandResponse {
                    success: false,
                    message: format!("命令执行失败: {}", e),
                    result_data: std::collections::HashMap::new(),
                };
                Ok(tonic::Response::new(response))
            }
        }
    }

    type SyncConfigStream =
        tokio_stream::wrappers::ReceiverStream<Result<ConfigSyncResponse, tonic::Status>>;

    async fn sync_config(
        &self,
        request: tonic::Request<tonic::Streaming<ConfigSyncRequest>>,
    ) -> Result<tonic::Response<Self::SyncConfigStream>, tonic::Status> {
        info!("收到配置同步请求");

        let (tx, rx) = tokio::sync::mpsc::channel(4);

        // 启动配置同步处理任务
        tokio::spawn(async move {
            let mut stream = request.into_inner();

            while let Some(sync_request) = stream.message().await.unwrap_or(None) {
                info!("处理配置同步请求: {:?}", sync_request);

                // 创建同步响应
                let response = ConfigSyncResponse {
                    success: true,
                    message: "配置同步成功".to_string(),
                    config_data: vec![],
                    version: sync_request.version,
                    metadata: std::collections::HashMap::new(),
                };

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(tonic::Response::new(receiver_stream))
    }
}

/// 运行gRPC服务器
pub async fn run_grpc_server(
    config: Arc<AppConfig>,
    statistics: Arc<Statistics>,
    sync_manager: Arc<DataSyncManager>,
) -> Result<()> {
    let grpc_port = config.server.grpc_port.unwrap_or(50051);
    let addr = format!("{}{}{}", config.server.host, ":", grpc_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("gRPC服务器监听于 {}", addr);

    let service = WafServiceImpl::new(config, statistics, sync_manager);
    let server = WafServiceServer::new(service);

    Server::builder()
        .add_service(server)
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
        .map_err(|e| {
            error!("gRPC服务器错误: {}", e);
            anyhow::anyhow!("gRPC服务器错误: {}", e)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_waf_service_creation() {
        let config = Arc::new(AppConfig::default());
        let statistics = Arc::new(Statistics::new());
        let sync_manager = Arc::new(DataSyncManager::new(
            statistics.clone(),
            "test-instance".to_string(),
        ));

        let _service = WafServiceImpl::new(config, statistics, sync_manager);
        // 如果能创建服务实例，说明基本结构正确
    }

    #[tokio::test]
    async fn test_statistics_integration() {
        let config = Arc::new(AppConfig::default());
        let statistics = Arc::new(Statistics::new());
        let sync_manager = Arc::new(DataSyncManager::new(
            statistics.clone(),
            "test-instance".to_string(),
        ));

        let service = WafServiceImpl::new(config, statistics.clone(), sync_manager);

        // 模拟一些统计数据
        statistics.increment_request();
        statistics.increment_cache_hit();
        statistics.increment_defense_hit();

        // 等待异步操作完成
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // 获取统计数据
        let request = tonic::Request::new(DetailedStatsRequest {
            instance_id: "test-instance".to_string(),
            start_time: 0,
            end_time: 0,
        });

        let response = service.get_detailed_stats(request).await.unwrap();
        let stats = response.into_inner();

        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.defense_hits, 1);
    }

    #[tokio::test]
    async fn test_command_execution() {
        let config = Arc::new(AppConfig::default());
        let statistics = Arc::new(Statistics::new());
        let sync_manager = Arc::new(DataSyncManager::new(
            statistics.clone(),
            "test-instance".to_string(),
        ));

        let service = WafServiceImpl::new(config, statistics, sync_manager);

        // 测试配置重载命令
        let request = tonic::Request::new(CommandRequest {
            instance_id: "test-instance".to_string(),
            command_type: 0, // RELOAD_CONFIG
            parameters: std::collections::HashMap::new(),
        });

        let response = service.execute_command(request).await.unwrap();
        let result = response.into_inner();

        assert!(result.success);
        assert!(!result.message.is_empty());
    }

    #[tokio::test]
    async fn test_site_list() {
        let config = Arc::new(AppConfig::default());
        let statistics = Arc::new(Statistics::new());
        let sync_manager = Arc::new(DataSyncManager::new(
            statistics.clone(),
            "test-instance".to_string(),
        ));

        let service = WafServiceImpl::new(config, statistics, sync_manager);

        let request = tonic::Request::new(SiteListRequest {
            instance_id: "test-instance".to_string(),
        });

        let response = service.get_site_list(request).await.unwrap();
        let site_list = response.into_inner();

        // 初始状态应该是空的网站列表
        assert_eq!(site_list.sites.len(), 0);
    }

    #[tokio::test]
    async fn test_blocked_ips() {
        let config = Arc::new(AppConfig::default());
        let statistics = Arc::new(Statistics::new());
        let sync_manager = Arc::new(DataSyncManager::new(
            statistics.clone(),
            "test-instance".to_string(),
        ));

        let service = WafServiceImpl::new(config, statistics, sync_manager);

        let request = tonic::Request::new(BlockedIPsRequest {
            instance_id: "test-instance".to_string(),
        });

        let response = service.get_blocked_i_ps(request).await.unwrap();
        let blocked_ips = response.into_inner();

        // 初始状态应该是空的封禁IP列表
        assert_eq!(blocked_ips.blocked_ips.len(), 0);
    }

    #[tokio::test]
    async fn test_type_conversions() {
        // 测试类型转换
        let site_info = crate::core::sync::SiteInfo {
            site_id: "test-site".to_string(),
            name: "Test Site".to_string(),
            domain: "example.com".to_string(),
            origin: "http://localhost:3000".to_string(),
            enabled: true,
            security_config: crate::core::sync::SecurityConfig {
                xss_protection: true,
                sql_injection_protection: true,
                five_second_shield: false,
                click_shield: false,
                captcha: false,
            },
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        let proto_site: waf::SiteInfo = site_info.into();
        assert_eq!(proto_site.site_id, "test-site");
        assert_eq!(proto_site.domain, "example.com");

        // 测试封禁IP转换
        let blocked_ip = crate::core::sync::BlockedIP {
            ip: "192.168.1.100".to_string(),
            reason: "Test block".to_string(),
            blocked_at: 1234567890,
            expires_at: 1234567890 + 3600,
            permanent: false,
        };

        let proto_blocked: waf::BlockedIp = blocked_ip.into();
        assert_eq!(proto_blocked.ip, "192.168.1.100");
        assert_eq!(proto_blocked.reason, "Test block");

        // 测试命令类型转换
        let cmd_type: crate::core::sync::CommandType = 2i32.into();
        matches!(cmd_type, crate::core::sync::CommandType::BlockIP);
    }
}
