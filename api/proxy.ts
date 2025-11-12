// Vercel Serverless Function - API 代理
// 一个简单、安全的 HTTPS API 反向代理
import type { VercelRequest, VercelResponse } from '@vercel/node';

// CORS 配置
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-request-session-id, x-request-id, cookie, set-cookie',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE, PATCH',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Max-Age': '86400'
};

// 允许转发的请求头白名单 - 扩展版本
const ALLOWED_HEADERS = [
  // 基础 HTTP headers
  'accept',
  'accept-encoding',
  'x-signature-version',
  'x-signature-timestamp',
  'x-signature-signature',
  'x-signature-vector',
  'accept-language',
  'content-type',
  'content-length',
  'content-encoding',
  'cache-control',
  'user-agent',
  // 认证相关
  'authorization',
  'www-authenticate',
  'cookie',
  'set-cookie',
  // API 常用 headers
  'x-api-key',
  'x-api-version',
  'x-client-version',
  'x-request-id',
  'x-request-session-id',
  'x-correlation-id',
  'x-trace-id',
  // 其他常用 API headers
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'x-custom-header',
  // 通用自定义 headers (x- 前缀)
  'x-forwarded-proto',
  'x-real-ip-override',
  // OAuth 和认证相关
  'origin',
  'referer'
];

// 需要移除的敏感请求头
const SENSITIVE_HEADERS = [
  'proxy-authenticate',
  'proxy-authorization',
  'x-real-ip',
  'cf-ray',
  'cf-visitor',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-request-id',
  'cf-worker',
  'cf-cache-status',
  'cf-edge-cache',
  'cf-zone-id',
  'cf-railgun',
  'cf-warp-tag-id',
  'cf-access-authenticated-user-email',
  'cf-access-jwt-assertion',
  'cf-access-client-id',
  'cf-access-client-secret',
  'cf-team-domain',
  'cf-access-token',
  'cf-super-bot-protection',
  'cf-bot-management-verified-bot',
  'cf-threat-score',
  'cf-mitigated',
  'cf-challenge-bypass'
];

// 验证目标域名
function isValidUrl(urlString: string): boolean {
  try {
    new URL(urlString);
    return true;
  } catch {
    return false;
  }
}

// 过滤请求头
function filterHeaders(headers: VercelRequest['headers']): Record<string, string> {
  const filteredHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (ALLOWED_HEADERS.includes(lowerKey)) {
      if (typeof value === 'string') {
        filteredHeaders[key] = value;
      } else if (Array.isArray(value)) {
        filteredHeaders[key] = value.join(', ');
      }
    }
  }
  return filteredHeaders;
}

function extractTargetUrl(pathname: string, search: string): string {
  let targetPath = pathname.substring(1);
  if (targetPath.startsWith('proxy/')) {
    targetPath = targetPath.substring(6);
  }
  
  // 如果没有协议，添加 https://
  if (!targetPath.startsWith('http://') && !targetPath.startsWith('https://')) {
    targetPath = 'https://' + targetPath;
  }
  
  // 添加查询参数
  if (search) {
    targetPath += search;
  }
  
  return targetPath;
}

// 处理代理请求
async function handleProxyRequest(req: VercelRequest, res: VercelResponse, targetUrl: string): Promise<void> {
  try {
    console.log('代理请求目标URL（含查询参数）:', targetUrl);
    
    if (!isValidUrl(targetUrl)) {
      res.status(400).json({
        error: '无效的URL格式',
        targetUrl: targetUrl
      });
      return;
    }
    
    const filteredHeaders = filterHeaders(req.headers);

    // 注意：由于使用白名单策略，敏感 headers 已经被过滤掉了
    // 这里的删除操作主要是为了确保安全性（防御性编程）
    SENSITIVE_HEADERS.forEach((header) => {
      delete filteredHeaders[header];
    });

    // 为特定域名添加必要的请求头
    const targetDomain = new URL(targetUrl).hostname;

    // 对 auth.augmentcode.com 的特殊处理
    if (targetDomain === 'auth.augmentcode.com') {
      // 确保 Cookie 被传递
      const cookieHeader = req.headers.cookie;
      if (cookieHeader) {
        filteredHeaders['cookie'] = cookieHeader;
        console.log('传递 Cookie 到 auth.augmentcode.com:', cookieHeader);
      }
      // 设置合适的 Origin 和 Referer
      filteredHeaders['origin'] = 'https://auth.augmentcode.com';
      filteredHeaders['referer'] = 'https://auth.augmentcode.com/';
    }

    // 对 portal.withorb.com 的特殊处理
    if (targetDomain === 'portal.withorb.com') {
      filteredHeaders['origin'] = 'https://portal.withorb.com';
      filteredHeaders['referer'] = 'https://portal.withorb.com/';
    }

    const proxyOptions: RequestInit = {
      method: req.method,
      headers: filteredHeaders
    };

    if (['POST', 'PUT', 'PATCH'].includes(req.method || '')) {
      // Vercel 已经解析了请求体
      if (req.body) {
        if (typeof req.body === 'string') {
          proxyOptions.body = req.body;
        } else if (typeof req.body === 'object') {
          proxyOptions.body = JSON.stringify(req.body);
        }
      }
    }

    console.log('代理请求详情:', {
      method: req.method,
      url: targetUrl,
      domain: targetDomain,
      hasCredentials: !!filteredHeaders['cookie'] || !!filteredHeaders['authorization'],
      headers: filteredHeaders
    });

    const proxyResponse = await fetch(targetUrl, proxyOptions);

    console.log('代理响应状态:', proxyResponse.status);

    // 设置 CORS 响应头
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    // 复制需要保留的响应头
    const headersToKeep = [
      'content-type',
      'content-length',
      'content-encoding',
      'set-cookie',
      'x-set-cookie',
      'location'
    ];

    headersToKeep.forEach((header) => {
      const value = proxyResponse.headers.get(header);
      if (value) {
        res.setHeader(header, value);
      }
    });

    // 设置响应状态
    res.status(proxyResponse.status);

    // 读取并发送响应体
    const responseBody = await proxyResponse.arrayBuffer();
    res.send(Buffer.from(responseBody));

  } catch (error) {
    console.error('代理请求失败:', error);
    const errorMessage = error instanceof Error ? error.message : '未知错误';

    // 设置 CORS 响应头
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    res.status(500).json({
      error: '代理请求失败',
      details: errorMessage,
      targetUrl: targetUrl
    });
  }
}

// Vercel Serverless Function Handler
export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { url = '', method } = req;

  // 解析 URL
  const parsedUrl = new URL(url, `https://${req.headers.host}`);
  const pathname = parsedUrl.pathname;
  const search = parsedUrl.search;

  console.log(`${method} ${pathname}${search}`);

  // 处理 CORS 预检请求
  if (method === 'OPTIONS') {
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    res.status(200).send('ok');
    return;
  }

  try {
    // 提取目标 URL 并代理请求
    const targetUrl = extractTargetUrl(pathname, search);
    await handleProxyRequest(req, res, targetUrl);
  } catch (error) {
    console.error('请求处理失败:', error);
    const errorMessage = error instanceof Error ? error.message : '服务器内部错误';

    // 设置 CORS 响应头
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    res.status(500).json({
      error: '服务器内部错误',
      details: errorMessage
    });
  }
}

