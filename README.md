# Mail Auth HTTP 服务

本项目是一个基于 Go 语言开发的 Nginx 邮件认证模块（auth_http），用于为大规模邮箱系统（支持万人级并发）提供高性能、可扩展的前置认证服务。

## 功能特性

- 支持 Nginx mail_auth HTTP 协议认证（POP3/IMAP/SMTP）
- 用户登录失败次数统计与自动锁定
- TOTP 二次认证支持，锁定后可用动态码解锁
- Redis 记录登录失败次数与锁定状态
- MySQL 存储用户密码及 TOTP 密钥
- 日志采用 zap，支持结构化输出
- 后端服务器自动分发
- 高并发安全设计

## 项目结构

```
.
├── main.go           # 服务入口，初始化组件并启动 HTTP 服务
├── auth.go           # 认证接口逻辑
├── redis.go          # Redis 操作相关
├── mysql.go          # MySQL 操作相关
├── totp.go           # TOTP 动态码相关
├── forward.go        # 后端分发逻辑
├── 并发.py           # 并发压测脚本
```

## 简单架构图

<img width="760" height="432" alt="image" src="https://github.com/user-attachments/assets/1eff1837-8883-42dc-93e6-ff28c7d0b443" />


## 快速开始

1. **环境准备**
   - Go 1.18+
   - MySQL 数据库
   - Redis 服务

2. **配置数据库和 Redis**
   - 在 `main.go` 中修改 Redis 地址、密码、数据库连接等参数
   - 初始化 MySQL 表结构（示例）：

     ```sql
     CREATE TABLE users (
       username VARCHAR(64) PRIMARY KEY,
       password VARCHAR(128) NOT NULL,
       totp_secret VARCHAR(32),
       totp_enabled TINYINT DEFAULT 0
     );
     ```

3. **启动服务**

   ```bash
   go run .
   ```

   默认监听 `:8089` 端口。

4. **Nginx 配置示例**

   ```
   mail {
       auth_http 127.0.0.1:8089/mail/auth;
       ...
   }
   ```

## 认证流程说明

1. Nginx 收到邮件登录请求，转发到 `/mail/auth` HTTP 接口。
2. 服务校验用户名、密码，统计失败次数，必要时锁定账户。
3. 支持 TOTP 动态码解锁。
4. 认证通过后返回后端服务器信息给 Nginx。

## 贡献指南

欢迎提交 Issue 或 PR，建议先提 Issue 讨论需求。

## License

MIT

---


如有问题欢迎联系或提交


