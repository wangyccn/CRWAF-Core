# CRWAF - 云锁Web应用防火墙

## 项目简介

CRWAF是一个高性能的Web应用防火墙，使用Rust语言开发，旨在提供强大的Web安全防护能力。

## 功能特点

- 高性能HTTP请求处理
- 基于规则的攻击检测
- 多种防御机制（五秒盾、点击盾、验证码等）
- 实时监控与统计
- gRPC通讯接口

## 技术栈

- Rust语言
- Tokio异步运行时
- Axum HTTP框架
- Tonic gRPC框架
- DashMap和LRU缓存

## 项目结构

```
├── src/
│   ├── core/       # 核心功能模块
│   ├── http/       # HTTP服务相关
│   └── rules/      # 规则引擎
├── config/         # 配置文件
├── proto/          # gRPC协议定义
└── rules/          # 规则定义
```

## 快速开始

### 编译

```bash
cargo build --release
```

### 运行

```bash
cargo run --release
```

## 配置

配置文件位于`config/config.toml`，可以根据需要修改。

## 规则

规则文件位于`rules/default.json`，可以根据需要添加或修改规则。

## 许可证

本项目采用MIT许可证。