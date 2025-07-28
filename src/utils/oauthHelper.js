/**
 * OAuth助手工具
 * 基于claude-code-login.js中的OAuth流程实现
 */

const crypto = require('crypto');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const axios = require('axios');
const logger = require('./logger');

// OAuth 配置常量 - 从claude-code-login.js提取
const OAUTH_CONFIG = {
    AUTHORIZE_URL: 'https://claude.ai/oauth/authorize',
    TOKEN_URL: 'https://console.anthropic.com/v1/oauth/token',
    CLIENT_ID: '9d1c250a-e61b-44d9-88ed-5944d1962f5e',
    REDIRECT_URI: 'https://console.anthropic.com/oauth/code/callback',
    SCOPES: 'org:create_api_key user:profile user:inference'
};

/**
 * 生成随机的 state 参数
 * @returns {string} 随机生成的 state (64字符hex)
 */
function generateState() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * 生成随机的 code verifier（PKCE）
 * @returns {string} base64url 编码的随机字符串
 */
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

/**
 * 生成 code challenge（PKCE）
 * @param {string} codeVerifier - code verifier 字符串
 * @returns {string} SHA256 哈希后的 base64url 编码字符串
 */
function generateCodeChallenge(codeVerifier) {
    return crypto.createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
}

/**
 * 生成授权 URL
 * @param {string} codeChallenge - PKCE code challenge
 * @param {string} state - state 参数
 * @returns {string} 完整的授权 URL
 */
function generateAuthUrl(codeChallenge, state) {
    const params = new URLSearchParams({
        code: 'true',
        client_id: OAUTH_CONFIG.CLIENT_ID,
        response_type: 'code',
        redirect_uri: OAUTH_CONFIG.REDIRECT_URI,
        scope: OAUTH_CONFIG.SCOPES,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state
    });

    return `${OAUTH_CONFIG.AUTHORIZE_URL}?${params.toString()}`;
}

/**
 * 生成OAuth授权URL和相关参数
 * @returns {{authUrl: string, codeVerifier: string, state: string, codeChallenge: string}}
 */
function generateOAuthParams() {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    const authUrl = generateAuthUrl(codeChallenge, state);
    
    return {
        authUrl,
        codeVerifier,
        state,
        codeChallenge
    };
}

/**
 * 验证代理配置
 * @param {object|null} proxyConfig - 代理配置对象
 * @returns {object} 验证结果 {isValid: boolean, error?: string}
 */
function validateProxyConfig(proxyConfig) {
    if (!proxyConfig) {
        return { isValid: true };
    }
    
    if (!proxyConfig.type) {
        return { isValid: false, error: 'Missing proxy type' };
    }
    
    if (!['socks5', 'http', 'https'].includes(proxyConfig.type)) {
        return { isValid: false, error: `Unsupported proxy type: ${proxyConfig.type}` };
    }
    
    if (!proxyConfig.host) {
        return { isValid: false, error: 'Missing proxy host' };
    }
    
    if (!proxyConfig.port || isNaN(proxyConfig.port) || proxyConfig.port < 1 || proxyConfig.port > 65535) {
        return { isValid: false, error: 'Invalid proxy port' };
    }
    
    // 验证认证信息（如果提供）
    if (proxyConfig.username && !proxyConfig.password) {
        return { isValid: false, error: 'Username provided but password is missing' };
    }
    
    return { isValid: true };
}

/**
 * 创建代理agent
 * @param {object|null} proxyConfig - 代理配置对象
 * @returns {object|null} 代理agent或null
 */
function createProxyAgent(proxyConfig) {
    if (!proxyConfig) {
        return null;
    }

    // 验证代理配置
    const validation = validateProxyConfig(proxyConfig);
    if (!validation.isValid) {
        logger.error('❌ Invalid proxy configuration', {
            error: validation.error,
            proxyConfig: {
                type: proxyConfig.type,
                host: proxyConfig.host,
                port: proxyConfig.port,
                hasAuth: !!(proxyConfig.username && proxyConfig.password)
            }
        });
        throw new Error(`Invalid proxy configuration: ${validation.error}`);
    }

    try {
        if (proxyConfig.type === 'socks5') {
            const auth = proxyConfig.username && proxyConfig.password ? `${proxyConfig.username}:${proxyConfig.password}@` : '';
            const socksUrl = `socks5://${auth}${proxyConfig.host}:${proxyConfig.port}`;
            logger.debug('🔗 Creating SOCKS5 proxy agent', {
                host: proxyConfig.host,
                port: proxyConfig.port,
                hasAuth: !!auth
            });
            return new SocksProxyAgent(socksUrl);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            const auth = proxyConfig.username && proxyConfig.password ? `${proxyConfig.username}:${proxyConfig.password}@` : '';
            const httpUrl = `${proxyConfig.type}://${auth}${proxyConfig.host}:${proxyConfig.port}`;
            logger.debug(`🔗 Creating ${proxyConfig.type.toUpperCase()} proxy agent`, {
                host: proxyConfig.host,
                port: proxyConfig.port,
                hasAuth: !!auth
            });
            return new HttpsProxyAgent(httpUrl);
        }
    } catch (error) {
        logger.error('❌ Failed to create proxy agent', {
            error: error.message,
            proxyConfig: {
                type: proxyConfig.type,
                host: proxyConfig.host,
                port: proxyConfig.port
            }
        });
        throw new Error(`Failed to create proxy agent: ${error.message}`);
    }

    return null;
}

/**
 * 等待指定时间
 * @param {number} ms - 等待时间（毫秒）
 * @returns {Promise<void>}
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 使用授权码交换访问令牌（带重试机制）
 * @param {string} authorizationCode - 授权码
 * @param {string} codeVerifier - PKCE code verifier
 * @param {string} state - state 参数
 * @param {object|null} proxyConfig - 代理配置（可选）
 * @param {number} maxRetries - 最大重试次数（默认3次）
 * @returns {Promise<object>} Claude格式的token响应
 */
async function exchangeCodeForTokens(authorizationCode, codeVerifier, state, proxyConfig = null, maxRetries = 3) {
    // 清理授权码，移除URL片段
    const cleanedCode = authorizationCode.split('#')[0]?.split('&')[0] ?? authorizationCode;
    
    const params = {
        grant_type: 'authorization_code',
        client_id: OAUTH_CONFIG.CLIENT_ID,
        code: cleanedCode,
        redirect_uri: OAUTH_CONFIG.REDIRECT_URI,
        code_verifier: codeVerifier,
        state: state
    };

    let lastError = null;
    
    // 重试逻辑
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        // 创建代理agent（每次重试都重新创建，避免连接状态问题）
        const agent = createProxyAgent(proxyConfig);

        try {
            logger.debug(`🔄 OAuth token exchange attempt ${attempt}/${maxRetries}`, {
                url: OAUTH_CONFIG.TOKEN_URL,
                codeLength: cleanedCode.length,
                codePrefix: cleanedCode.substring(0, 10) + '...',
                hasProxy: !!proxyConfig,
                proxyType: proxyConfig?.type || 'none',
                attempt: attempt
            });

            const response = await axios.post(OAUTH_CONFIG.TOKEN_URL, params, {
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'claude-cli/1.0.56 (external, cli)',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Referer': 'https://claude.ai/',
                    'Origin': 'https://claude.ai'
                },
                httpsAgent: agent,
                timeout: 30000
            });

            logger.success('✅ OAuth token exchange successful', {
                status: response.status,
                hasAccessToken: !!response.data?.access_token,
                hasRefreshToken: !!response.data?.refresh_token,
                scopes: response.data?.scope,
                attempt: attempt
            });

            const data = response.data;
            
            // 返回Claude格式的token数据
            return {
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                expiresAt: (Math.floor(Date.now() / 1000) + data.expires_in) * 1000,
                scopes: data.scope ? data.scope.split(' ') : ['user:inference', 'user:profile'],
                isMax: true
            };
        } catch (error) {
            lastError = error;
            
            // 对于某些错误类型，不进行重试
            const shouldNotRetry = error.response && (
                error.response.status === 400 || // 无效请求参数
                error.response.status === 401 || // 认证失败
                error.response.status === 403    // 权限不足
            );
            
            if (shouldNotRetry) {
                logger.error('❌ OAuth token exchange failed with non-retryable error', {
                    status: error.response?.status,
                    statusText: error.response?.statusText,
                    attempt: attempt
                });
                break; // 退出重试循环
            }
            
            // 记录重试信息
            const isNetworkError = !error.response;
            const errorType = isNetworkError ? 'network' : 'server';
            
            logger.warn(`⚠️ OAuth token exchange attempt ${attempt} failed (${errorType} error)`, {
                message: error.message,
                code: error.code,
                status: error.response?.status,
                hasProxy: !!proxyConfig,
                willRetry: attempt < maxRetries
            });
            
            // 如果不是最后一次尝试，等待后重试
            if (attempt < maxRetries) {
                const waitTime = Math.min(1000 * Math.pow(2, attempt - 1), 5000); // 指数退避，最多5秒
                logger.debug(`⏳ Waiting ${waitTime}ms before retry...`);
                await sleep(waitTime);
                continue; // 继续下一次尝试
            }
        }
    }
    
    // 所有重试都失败了，抛出最后一个错误
    if (lastError) {
        // 处理axios错误响应
        if (lastError.response) {
            // 服务器返回了错误状态码
            const status = lastError.response.status;
            const errorData = lastError.response.data;
            
            logger.error('❌ OAuth token exchange failed with server error (after retries)', {
                status: status,
                statusText: lastError.response.statusText,
                headers: lastError.response.headers,
                data: errorData,
                codeLength: cleanedCode.length,
                codePrefix: cleanedCode.substring(0, 10) + '...',
                totalAttempts: maxRetries
            });
            
            // 尝试从错误响应中提取有用信息
            let errorMessage = `HTTP ${status}`;
            
            if (errorData) {
                if (typeof errorData === 'string') {
                    errorMessage += `: ${errorData}`;
                } else if (errorData.error) {
                    errorMessage += `: ${errorData.error}`;
                    if (errorData.error_description) {
                        errorMessage += ` - ${errorData.error_description}`;
                    }
                } else {
                    errorMessage += `: ${JSON.stringify(errorData)}`;
                }
            }
            
            throw new Error(`Token exchange failed after ${maxRetries} attempts: ${errorMessage}`);
        } else if (lastError.request) {
            // 请求被发送但没有收到响应
            logger.error('❌ OAuth token exchange failed with network error (after retries)', {
                message: lastError.message,
                code: lastError.code,
                hasProxy: !!proxyConfig,
                totalAttempts: maxRetries
            });
            throw new Error(`Token exchange failed after ${maxRetries} attempts: No response from server (network error or timeout)`);
        } else {
            // 其他错误
            logger.error('❌ OAuth token exchange failed with unknown error (after retries)', {
                message: lastError.message,
                stack: lastError.stack,
                totalAttempts: maxRetries
            });
            throw new Error(`Token exchange failed after ${maxRetries} attempts: ${lastError.message}`);
        }
    }
    
    // 这种情况理论上不应该发生，但为了安全起见
    throw new Error(`Token exchange failed after ${maxRetries} attempts: Unknown error`);
}

/**
 * 解析回调 URL 或授权码
 * @param {string} input - 完整的回调 URL 或直接的授权码
 * @returns {string} 授权码
 */
function parseCallbackUrl(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('请提供有效的授权码或回调 URL');
    }

    const trimmedInput = input.trim();
    
    // 情况1: 尝试作为完整URL解析
    if (trimmedInput.startsWith('http://') || trimmedInput.startsWith('https://')) {
        try {
            const urlObj = new URL(trimmedInput);
            const authorizationCode = urlObj.searchParams.get('code');

            if (!authorizationCode) {
                throw new Error('回调 URL 中未找到授权码 (code 参数)');
            }

            return authorizationCode;
        } catch (error) {
            if (error.message.includes('回调 URL 中未找到授权码')) {
                throw error;
            }
            throw new Error('无效的 URL 格式，请检查回调 URL 是否正确');
        }
    }
    
    // 情况2: 直接的授权码（可能包含URL fragments）
    // 参考claude-code-login.js的处理方式：移除URL fragments和参数
    const cleanedCode = trimmedInput.split('#')[0]?.split('&')[0] ?? trimmedInput;
    
    // 验证授权码格式（Claude的授权码通常是base64url格式）
    if (!cleanedCode || cleanedCode.length < 10) {
        throw new Error('授权码格式无效，请确保复制了完整的 Authorization Code');
    }
    
    // 基本格式验证：授权码应该只包含字母、数字、下划线、连字符
    const validCodePattern = /^[A-Za-z0-9_-]+$/;
    if (!validCodePattern.test(cleanedCode)) {
        throw new Error('授权码包含无效字符，请检查是否复制了正确的 Authorization Code');
    }
    
    return cleanedCode;
}

/**
 * 格式化为Claude标准格式
 * @param {object} tokenData - token数据
 * @returns {object} claudeAiOauth格式的数据
 */
function formatClaudeCredentials(tokenData) {
    return {
        claudeAiOauth: {
            accessToken: tokenData.accessToken,
            refreshToken: tokenData.refreshToken,
            expiresAt: tokenData.expiresAt,
            scopes: tokenData.scopes,
            isMax: tokenData.isMax
        }
    };
}

module.exports = {
    OAUTH_CONFIG,
    generateOAuthParams,
    exchangeCodeForTokens,
    parseCallbackUrl,
    formatClaudeCredentials,
    generateState,
    generateCodeVerifier,
    generateCodeChallenge,
    generateAuthUrl,
    createProxyAgent
};