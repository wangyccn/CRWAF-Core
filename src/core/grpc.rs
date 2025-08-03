use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tracing::{error, info};

use crate::core::config::AppConfig;

// 导入生成的proto代码
pub mod waf {
    tonic::include_proto!("waf");
}

use waf::waf_service_server::{WafService, WafServiceServer};
use waf::*;

/// WAF gRPC服务实现
pub struct WafServiceImpl {
    #[allow(dead_code)]
    config: Arc<AppConfig>,
}

impl WafServiceImpl {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self { config }
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
}

/// 运行gRPC服务器
pub async fn run_grpc_server(config: Arc<AppConfig>) -> Result<()> {
    let addr = format!("{}:{}", "0.0.0.0", 50051);
    let listener = TcpListener::bind(&addr).await?;
    info!("gRPC服务器监听于 {}", addr);

    let service = WafServiceImpl::new(config);
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