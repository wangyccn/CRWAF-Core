use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use reqwest::Client;
use serde_json::Value;

/// 第一阶段功能测试脚本
/// 测试CRWAF项目的所有第一阶段功能

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 开始CRWAF第一阶段功能验收测试");
    println!("=".repeat(50));

    let mut test_results = Vec::new();

    // 1. 测试项目结构
    println!("\n📁 测试项目结构...");
    test_results.push(test_project_structure().await);

    // 2. 测试配置加载
    println!("\n⚙️  测试配置加载...");
    test_results.push(test_config_loading().await);

    // 3. 测试规则文件解析
    println!("\n📜 测试规则文件解析...");
    test_results.push(test_rule_parsing().await);

    // 4. 启动服务器进行测试
    println!("\n🔄 启动CRWAF服务器...");
    let server_handle = start_server().await?;
    
    // 等待服务器启动
    sleep(Duration::from_secs(3)).await;

    // 5. 测试HTTP服务器
    println!("\n🌐 测试HTTP服务器功能...");
    test_results.push(test_http_server().await);

    // 6. 测试gRPC服务器
    println!("\n📡 测试gRPC服务器功能...");
    test_results.push(test_grpc_server().await);

    // 7. 测试攻击检测
    println!("\n🛡️  测试攻击检测功能...");
    test_results.push(test_attack_detection().await);

    // 8. 测试验证码系统
    println!("\n🖼️  测试验证码系统...");
    test_results.push(test_captcha_system().await);

    // 9. 测试身份识别
    println!("\n🆔 测试身份识别系统...");
    test_results.push(test_identity_system().await);

    // 10. 测试缓存系统
    println!("\n💾 测试缓存系统...");
    test_results.push(test_cache_system().await);

    // 11. 测试日志系统
    println!("\n📝 测试日志系统...");
    test_results.push(test_logging_system().await);

    // 12. 测试系统操作
    println!("\n🔧 测试系统操作...");
    test_results.push(test_system_operations().await);

    // 停止服务器
    if let Some(handle) = server_handle {
        handle.abort();
    }

    // 生成测试报告
    println!("\n📊 生成测试报告...");
    generate_test_report(&test_results).await;

    Ok(())
}

struct TestResult {
    name: String,
    passed: bool,
    details: String,
    score: f32,
}

impl TestResult {
    fn new(name: &str, passed: bool, details: &str) -> Self {
        Self {
            name: name.to_string(),
            passed,
            details: details.to_string(),
            score: if passed { 1.0 } else { 0.0 },
        }
    }

    fn partial(name: &str, score: f32, details: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: score > 0.5,
            details: details.to_string(),
            score,
        }
    }
}

async fn test_project_structure() -> TestResult {
    let mut score = 0.0;
    let mut details = Vec::new();

    // 检查核心目录结构
    let required_dirs = [
        "src/core",
        "src/http", 
        "src/rules",
        "config",
        "rules",
        "proto",
    ];

    for dir in &required_dirs {
        if Path::new(dir).exists() {
            score += 1.0 / required_dirs.len() as f32;
            details.push(format!("✓ {}", dir));
        } else {
            details.push(format!("✗ {}", dir));
        }
    }

    // 检查核心文件
    let required_files = [
        "src/main.rs",
        "config/config.toml",
        "Cargo.toml",
        "build.rs",
        "proto/waf.proto",
    ];

    for file in &required_files {
        if Path::new(file).exists() {
            score += 1.0 / required_files.len() as f32;
            details.push(format!("✓ {}", file));
        } else {
            details.push(format!("✗ {}", file));
        }
    }

    TestResult::partial("项目结构", score / 2.0, &details.join("\n"))
}

async fn test_config_loading() -> TestResult {
    let config_path = "config/config.toml";
    
    if !Path::new(config_path).exists() {
        return TestResult::new("配置加载", false, "配置文件不存在");
    }

    match fs::read_to_string(config_path) {
        Ok(content) => {
            let required_sections = ["server", "cache", "log", "rules"];
            let mut found_sections = 0;
            
            for section in &required_sections {
                if content.contains(&format!("[{}]", section)) {
                    found_sections += 1;
                }
            }

            let score = found_sections as f32 / required_sections.len() as f32;
            TestResult::partial(
                "配置加载", 
                score, 
                &format!("找到 {}/{} 个必需的配置段", found_sections, required_sections.len())
            )
        }
        Err(e) => TestResult::new("配置加载", false, &format!("读取配置文件失败: {}", e)),
    }
}

async fn test_rule_parsing() -> TestResult {
    let mut score = 0.0;
    let mut details = Vec::new();

    let rule_files = ["rules/default.json", "rules/custom.json"];
    
    for rule_file in &rule_files {
        if Path::new(rule_file).exists() {
            match fs::read_to_string(rule_file) {
                Ok(content) => {
                    match serde_json::from_str::<Value>(&content) {
                        Ok(_) => {
                            score += 0.5;
                            details.push(format!("✓ {} 解析成功", rule_file));
                        }
                        Err(e) => {
                            details.push(format!("✗ {} 解析失败: {}", rule_file, e));
                        }
                    }
                }
                Err(e) => {
                    details.push(format!("✗ {} 读取失败: {}", rule_file, e));
                }
            }
        } else {
            details.push(format!("✗ {} 不存在", rule_file));
        }
    }

    TestResult::partial("规则文件解析", score, &details.join("\n"))
}

async fn start_server() -> Result<Option<tokio::task::JoinHandle<()>>, Box<dyn std::error::Error>> {
    // 启动CRWAF服务器
    let handle = tokio::spawn(async {
        if let Err(e) = tokio::process::Command::new("cargo")
            .arg("run")
            .arg("--release")
            .spawn()
        {
            eprintln!("启动服务器失败: {}", e);
        }
    });

    Ok(Some(handle))
}

async fn test_http_server() -> TestResult {
    let client = Client::new();
    let base_url = "http://127.0.0.1:8080";

    // 测试服务器连接
    match client.get(base_url).timeout(Duration::from_secs(5)).send().await {
        Ok(response) => {
            TestResult::new(
                "HTTP服务器", 
                true, 
                &format!("服务器响应状态: {}", response.status())
            )
        }
        Err(e) => {
            TestResult::new("HTTP服务器", false, &format!("连接失败: {}", e))
        }
    }
}

async fn test_grpc_server() -> TestResult {
    // 测试gRPC服务器连接
    let grpc_endpoint = "http://127.0.0.1:50051";
    
    // 简单的连接测试
    match tokio::net::TcpStream::connect("127.0.0.1:50051").await {
        Ok(_) => TestResult::new("gRPC服务器", true, "gRPC端口可连接"),
        Err(e) => TestResult::new("gRPC服务器", false, &format!("连接失败: {}", e)),
    }
}

async fn test_attack_detection() -> TestResult {
    let client = Client::new();
    let base_url = "http://127.0.0.1:8080";
    let mut score = 0.0;
    let mut details = Vec::new();

    // 测试XSS检测
    let xss_payloads = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
    ];

    for payload in &xss_payloads {
        let url = format!("{}/?test={}", base_url, urlencoding::encode(payload));
        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().as_u16() == 403 || response.status().as_u16() == 406 {
                    score += 1.0 / (xss_payloads.len() * 4) as f32;
                    details.push(format!("✓ XSS检测: {}", payload));
                } else {
                    details.push(format!("✗ XSS检测失败: {}", payload));
                }
            }
            Err(_) => {
                details.push(format!("✗ XSS测试请求失败: {}", payload));
            }
        }
    }

    // 测试SQL注入检测
    let sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users --",
    ];

    for payload in &sql_payloads {
        let url = format!("{}/?id={}", base_url, urlencoding::encode(payload));
        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().as_u16() == 403 || response.status().as_u16() == 406 {
                    score += 1.0 / (xss_payloads.len() * 4) as f32;
                    details.push(format!("✓ SQL注入检测: {}", payload));
                } else {
                    details.push(format!("✗ SQL注入检测失败: {}", payload));
                }
            }
            Err(_) => {
                details.push(format!("✗ SQL注入测试请求失败: {}", payload));
            }
        }
    }

    TestResult::partial("攻击检测", score, &details.join("\n"))
}

async fn test_captcha_system() -> TestResult {
    let client = Client::new();
    let captcha_url = "http://127.0.0.1:8080/captcha";

    match client.get(captcha_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                TestResult::new("验证码系统", true, "验证码端点可访问")
            } else {
                TestResult::new("验证码系统", false, &format!("验证码端点返回: {}", response.status()))
            }
        }
        Err(e) => TestResult::new("验证码系统", false, &format!("访问验证码端点失败: {}", e)),
    }
}

async fn test_identity_system() -> TestResult {
    let client = Client::new();
    let base_url = "http://127.0.0.1:8080";

    match client.get(base_url).send().await {
        Ok(response) => {
            // 检查响应头中是否有身份标识相关的头部
            let headers = response.headers();
            let has_session_id = headers.get("X-Session-ID").is_some() || 
                               headers.get("Set-Cookie").is_some();
            
            TestResult::new(
                "身份识别", 
                has_session_id, 
                if has_session_id { "检测到会话标识" } else { "未检测到会话标识" }
            )
        }
        Err(e) => TestResult::new("身份识别", false, &format!("测试失败: {}", e)),
    }
}

async fn test_cache_system() -> TestResult {
    // 检查缓存目录是否存在
    let cache_dir = "cache";
    let file_cache_exists = Path::new(cache_dir).exists();
    
    TestResult::new(
        "缓存系统", 
        file_cache_exists, 
        if file_cache_exists { "缓存目录存在" } else { "缓存目录不存在" }
    )
}

async fn test_logging_system() -> TestResult {
    let log_dir = "logs";
    let log_exists = Path::new(log_dir).exists();
    
    if !log_exists {
        return TestResult::new("日志系统", false, "日志目录不存在");
    }

    // 检查日志文件
    let mut score = 0.0;
    let mut details = Vec::new();

    if let Ok(entries) = fs::read_dir(log_dir) {
        let log_files: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        
        if !log_files.is_empty() {
            score = 1.0;
            details.push(format!("找到 {} 个日志文件", log_files.len()));
        } else {
            details.push("日志目录为空".to_string());
        }
    }

    TestResult::partial("日志系统", score, &details.join("\n"))
}

async fn test_system_operations() -> TestResult {
    // 测试系统操作功能（缓存清理、重启等）
    // 这里主要检查相关的代码结构是否存在
    let operations = [
        "src/core/cache_manager.rs",
        "src/core/config.rs",
        "src/rules/engine.rs",
    ];

    let mut score = 0.0;
    let mut details = Vec::new();

    for op_file in &operations {
        if Path::new(op_file).exists() {
            score += 1.0 / operations.len() as f32;
            details.push(format!("✓ {}", op_file));
        } else {
            details.push(format!("✗ {}", op_file));
        }
    }

    TestResult::partial("系统操作", score, &details.join("\n"))
}

async fn generate_test_report(results: &[TestResult]) {
    println!("\n📊 测试报告");
    println!("=".repeat(50));

    let total_tests = results.len();
    let passed_tests = results.iter().filter(|r| r.passed).count();
    let total_score: f32 = results.iter().map(|r| r.score).sum();
    let average_score = total_score / total_tests as f32;

    println!("总测试项: {}", total_tests);
    println!("通过测试: {}", passed_tests);
    println!("总体得分: {:.1}%", average_score * 100.0);
    println!();

    for result in results {
        let status = if result.passed { "✅ PASS" } else { "❌ FAIL" };
        println!("{} {} (得分: {:.1}%)", status, result.name, result.score * 100.0);
        if !result.details.is_empty() {
            for line in result.details.lines() {
                println!("   {}", line);
            }
        }
        println!();
    }

    // 生成测试报告文件
    let report_content = format!(
        "# CRWAF 第一阶段功能测试报告\n\n\
        生成时间: {}\n\
        总测试项: {}\n\
        通过测试: {}\n\
        总体得分: {:.1}%\n\n\
        ## 详细结果\n\n{}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        total_tests,
        passed_tests,
        average_score * 100.0,
        results.iter().map(|r| {
            format!(
                "### {}\n状态: {}\n得分: {:.1}%\n详情:\n```\n{}\n```\n",
                r.name,
                if r.passed { "PASS" } else { "FAIL" },
                r.score * 100.0,
                r.details
            )
        }).collect::<Vec<_>>().join("\n")
    );

    if let Err(e) = fs::write("test_report.md", report_content) {
        eprintln!("保存测试报告失败: {}", e);
    } else {
        println!("📄 测试报告已保存至: test_report.md");
    }

    // 验收结论
    println!("🎯 验收结论:");
    if average_score >= 0.8 {
        println!("✅ 第一阶段功能验收通过！项目核心功能已实现，可以进入第二阶段开发。");
    } else if average_score >= 0.6 {
        println!("⚠️  第一阶段功能基本完成，但仍有部分问题需要修复后再进入下一阶段。");
    } else {
        println!("❌ 第一阶段功能验收未通过，需要修复关键问题后重新测试。");
    }
}