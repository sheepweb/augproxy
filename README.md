# AugProxy

一个简单、安全的 HTTPS API 反向代理服务，部署在 Vercel Serverless Functions 上。

## 功能特性

- ✅ 完整的 CORS 支持
- ✅ 请求头白名单过滤
- ✅ 敏感请求头自动移除
- ✅ 特定域名特殊处理（auth.augmentcode.com, portal.withorb.com）
- ✅ 自动 HTTPS 协议补全
- ✅ 流式响应支持
- ✅ 60秒函数超时时间

## 快速开始

### 本地开发

```bash
# 安装依赖
npm install

# 启动本地开发服务器
npm run dev
```

### 部署到 Vercel

```bash
# 首次部署
npx vercel

# 生产部署
npx vercel --prod
```

## 使用方式

部署后，所有请求都会被代理：

```bash
# 基本用法
https://your-domain.vercel.app/api.example.com/endpoint

# 带 proxy/ 前缀
https://your-domain.vercel.app/proxy/api.example.com/endpoint

# 带查询参数
https://your-domain.vercel.app/api.example.com/endpoint?key=value
```

## 环境变量

无需配置环境变量，开箱即用。

## 技术栈

- TypeScript
- Vercel Serverless Functions
- Node.js 18+ (原生 fetch API)

## License

MIT

