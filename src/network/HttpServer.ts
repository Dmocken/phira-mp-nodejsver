import express from 'express';
import { createServer, Server } from 'http';
import path from 'path';
import fs from 'fs';
import session, { SessionData } from 'express-session';
import crypto from 'crypto';
import { Logger } from '../logging/logger';
import { ServerConfig } from '../config/config';
import { RoomManager } from '../domain/rooms/RoomManager';
import { ProtocolHandler } from '../domain/protocol/ProtocolHandler';
import * as $Captcha20230305 from '@alicloud/captcha20230305';
import * as $OpenApi from '@alicloud/openapi-client';

interface AdminSession extends SessionData {
  isAdmin?: boolean;
}

interface LoginAttempt {
  count: number;
  lastAttempt: number;
}

export class HttpServer {
  private readonly app: express.Application;
  private readonly server: Server;
  private readonly loginAttempts = new Map<string, LoginAttempt>();
  private readonly blacklistedIps = new Set<string>();
  private aliyunCaptchaClient?: $Captcha20230305.default;
  private sessionParser: express.RequestHandler;
  private readonly blacklistFile = path.join(process.cwd(), 'logs', 'login_blacklist.log');
  
  constructor(
    private readonly config: ServerConfig,
    private readonly logger: Logger,
    private readonly roomManager: RoomManager,
    private readonly protocolHandler: ProtocolHandler,
  ) {
    this.app = express();
    this.server = createServer(this.app);

    // Initialize session parser
    this.sessionParser = session({
      secret: this.config.sessionSecret,
      resave: false,
      saveUninitialized: true,
      cookie: { 
          secure: process.env.NODE_ENV === 'production', // Enable secure cookies in production
          httpOnly: true,
          sameSite: 'lax', // CSRF protection
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
      } 
    });

    this.setupMiddleware();
    this.setupRoutes();
    this.initAliyunCaptchaClient();
    this.loadBlacklist();
    
    // Cleanup expired login attempts every hour to prevent memory leak
    setInterval(() => {
        const now = Date.now();
        for (const [ip, attempt] of this.loginAttempts.entries()) {
            if (now - attempt.lastAttempt > 15 * 60 * 1000) { // 15 minutes expiration
                this.loginAttempts.delete(ip);
            }
        }
    }, 60 * 60 * 1000);
  }

  private loadBlacklist(): void {
    if (fs.existsSync(this.blacklistFile)) {
        try {
            const data = fs.readFileSync(this.blacklistFile, 'utf8');
            const lines = data.split('\n');
            lines.forEach(line => {
                const match = line.match(/IP: ([\d.]+)/);
                if (match) this.blacklistedIps.add(match[1]);
            });
            this.logger.info(`已从文件加载 ${this.blacklistedIps.size} 个黑名单 IP。`);
        } catch (e) {
            this.logger.error(`加载黑名单文件失败: ${e}`);
        }
    }
  }

  private logToBlacklist(ip: string, username: string): void {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] IP: ${ip}, Username Attempted: ${username}, Reason: Too many failures\n`;
    try {
        fs.appendFileSync(this.blacklistFile, logEntry);
        this.blacklistedIps.add(ip);
    } catch (e) {
        this.logger.error(`写入黑名单日志失败: ${e}`);
    }
  }

  private initAliyunCaptchaClient(): void {
    if (this.config.captchaProvider === 'aliyun' && this.config.aliyunAccessKeyId && this.config.aliyunAccessKeySecret) {
      try {
        const config = new $OpenApi.Config({
          accessKeyId: this.config.aliyunAccessKeyId,
          accessKeySecret: this.config.aliyunAccessKeySecret,
          endpoint: 'captcha.cn-shanghai.aliyuncs.com',
          regionId: 'cn-shanghai',
        });
        this.aliyunCaptchaClient = new $Captcha20230305.default(config);
        this.logger.info('阿里云验证码 2.0 客户端已初始化');
      } catch (error) {
        this.logger.error(`初始化阿里云验证码客户端失败: ${String(error)}`);
      }
    }
  }

  private async verifyCaptcha(req: express.Request, ip: string): Promise<{ success: boolean; message?: string }> {
      const provider = this.config.captchaProvider;
      
      if (provider === 'none') {
          return { success: true };
      }

      if (provider === 'cloudflare') {
          const turnstileToken = req.body['cf-turnstile-response'];
          if (!this.config.turnstileSecretKey) return { success: true };
          if (!turnstileToken) return { success: false, message: 'Turnstile verification failed (missing token).' };

          try {
              const verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
              const formData = new URLSearchParams();
              formData.append('secret', this.config.turnstileSecretKey);
              formData.append('response', turnstileToken as string);
              formData.append('remoteip', ip);

              const result = await fetch(verifyUrl, {
                  method: 'POST',
                  body: formData,
              });
              
              const outcome = await result.json() as any;
              if (!outcome.success) {
                  this.logger.warn(`IP ${ip} 的 Turnstile 验证失败: ${JSON.stringify(outcome)}`);
                  return { success: false, message: 'Turnstile verification failed. Please try again.' };
              }
              return { success: true };
          } catch (error) {
              this.logger.error(`Turnstile 验证错误: ${String(error)}`);
              return { success: false, message: 'Internal server error during verification.' };
          }
      }

      if (provider === 'aliyun') {
          const captchaVerifyParam = req.body['captchaVerifyParam'] || req.body['captcha_verify_param'];
          if (!this.aliyunCaptchaClient || !this.config.aliyunCaptchaSceneId) {
              this.logger.error('阿里云验证码客户端未初始化或 Scene ID 缺失');
              return { success: false, message: 'Captcha service configuration error.' };
          }
          if (!captchaVerifyParam) return { success: false, message: 'Aliyun Captcha verification failed (missing param).' };

          try {
              const verifyIntelligentCaptchaRequest = new $Captcha20230305.VerifyIntelligentCaptchaRequest({
                  captchaVerifyParam: captchaVerifyParam,
                  sceneId: this.config.aliyunCaptchaSceneId,
              });
              
              const response = await this.aliyunCaptchaClient.verifyIntelligentCaptcha(verifyIntelligentCaptchaRequest);
              
              this.logger.info(`IP ${ip} 的阿里云 2.0 API 响应: ${JSON.stringify(response.body)}`);

              const verifyResult = response.body?.result?.verifyResult;
              if (response.body && response.body.result && (verifyResult === true || (verifyResult as any) === 'true')) {
                  this.logger.info(`IP ${ip} 的阿里云验证码验证成功`);
                  return { success: true };
              } else {
                  this.logger.warn(`IP ${ip} 的阿里云验证码验证失败: ${JSON.stringify(response.body)}`);
                  let msg = response.body?.message || 'Verification failed';
                  if (response.body?.result?.verifyCode === 'F023') {
                      msg = 'SceneId mismatch (F023). Please check your Aliyun console.';
                  }
                  return { success: false, message: msg };
              }
          } catch (error: any) {
              this.logger.error(`阿里云验证码 SDK 错误: ${error.message} (Code: ${error.code})`);
              return { success: false, message: `Captcha service connection error: ${error.message}` };
          }
      }

      return { success: true };
  }

  private setupMiddleware(): void {
    // Body parser for form data and JSON
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(express.json());

    // Session management
    // Check for insecure default secret
    if (this.config.sessionSecret === 'a-very-insecure-secret-change-it') {
        this.logger.warn('安全警告：正在使用默认的 Session Secret。请在 .env 文件中设置 SESSION_SECRET。');
    }

    this.app.use(this.sessionParser);
    
    // CORS middleware to allow other servers to fetch data
    this.app.use((_req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*'); // Allow any server to request
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-Admin-Secret');
        next();
    });
  }

  private adminAuth(req: express.Request, res: express.Response, next: express.NextFunction): void {
    const isAdmin = (req.session as AdminSession).isAdmin;
    const providedSecret = req.header('X-Admin-Secret') || (req.query.admin_secret as string);

    const isSecretValid = providedSecret ? this.verifyAdminSecret(providedSecret) : false;

    if (isAdmin || isSecretValid) {
        // If authenticated via secret but not session, we can optionally mark session as admin
        if (!isAdmin && (req.session as AdminSession)) {
            (req.session as AdminSession).isAdmin = true;
        }
        return next();
    }

    res.status(403).json({ error: 'Forbidden: Admin access required' });
  }

  private verifyAdminSecret(providedSecret: string): boolean {
    if (!this.config.adminSecret || this.config.adminSecret.trim() === '') return false;

    try {
      // 使用 ADMIN_SECRET 的 SHA256 作为 32 字节 Key
      const key = crypto.createHash('sha256').update(this.config.adminSecret).digest();
      const data = Buffer.from(providedSecret, 'hex');
      
      if (data.length < 17) return false;

      const iv = data.subarray(0, 16);
      const encrypted = data.subarray(16);
      
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encrypted, undefined, 'utf8');
      decrypted += decipher.final('utf8');

      // 获取当前日期 (YYYY-MM-DD)
      const now = new Date();
      const dateStr = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
      
      // 验证格式: {日期}_{SECRET}_xy521
      const expected = `${dateStr}_${this.config.adminSecret}_xy521`;
      
      return decrypted === expected;
    } catch (e) {
      this.logger.debug(`管理员密钥解密失败: ${e}`);
      return false;
    }
  }

  private setupRoutes(): void {
    const publicPath = path.join(__dirname, '../../public');
    this.app.use(express.static(publicPath));
    this.logger.info(`正在从 ${publicPath} 提供静态文件`);

    this.app.get('/admin', (req, res) => {
      if ((req.session as AdminSession).isAdmin) {
        return res.redirect('/');
      }
      res.sendFile(path.join(publicPath, 'admin.html'));
    });

    this.app.post('/api/test/verify-captcha', async (req, res) => {
        const ip = req.ip || req.socket.remoteAddress || 'unknown';
        const result = await this.verifyCaptcha(req, ip);
        res.json(result);
    });

    this.app.post('/login', async (req, res) => {
      const { username, password } = req.body;
      const ip = req.ip || req.socket.remoteAddress || 'unknown';

      if (this.blacklistedIps.has(ip)) {
          return res.status(403).send('由于您多次尝试登录失败，已被系统拉入登录黑名单，如需要解除，请联系服务器管理员');
      }

      if (!username || !password) {
        return res.status(400).send('Username and password are required.');
      }

      const captchaResult = await this.verifyCaptcha(req, ip);
      if (!captchaResult.success) {
          return res.status(400).send(captchaResult.message || 'Captcha verification failed.');
      }

      const now = Date.now();
      let attempt = this.loginAttempts.get(ip);

      if (!attempt) {
        attempt = { count: 0, lastAttempt: now };
        this.loginAttempts.set(ip, attempt);
      }

      // Reset count if last attempt was more than 2 minutes ago
      if (now - attempt.lastAttempt > 2 * 60 * 1000) {
          attempt.count = 0;
      }

      if (attempt.count >= 8) {
          this.logToBlacklist(ip, String(username));
          return res.status(403).send('由于您多次尝试登录失败，已被系统拉入登录黑名单，如需要解除，请联系服务器管理员');
      }

      // Timing Safe Comparison
      const inputUsernameHash = crypto.createHash('sha256').update(String(username)).digest();
      const targetUsernameHash = crypto.createHash('sha256').update(this.config.adminName).digest();
      const inputPasswordHash = crypto.createHash('sha256').update(String(password)).digest();
      const targetPasswordHash = crypto.createHash('sha256').update(this.config.adminPassword).digest();

      // We use timingSafeEqual on hashes (which are fixed length)
      const usernameMatch = crypto.timingSafeEqual(inputUsernameHash, targetUsernameHash);
      const passwordMatch = crypto.timingSafeEqual(inputPasswordHash, targetPasswordHash);

      if (usernameMatch && passwordMatch) {
        // Success
        this.loginAttempts.delete(ip); // Clear failed attempts
        
        // Regenerate session to prevent fixation attacks
        try {
            await new Promise<void>((resolve, reject) => {
                req.session.regenerate((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
            
            (req.session as AdminSession).isAdmin = true;
            const safeUsername = String(username).substring(0, 50); // Limit log length
            this.logger.info(`管理员用户 '${safeUsername}' 从 ${ip} 登录成功。`);
            return res.redirect('/');
        } catch (err) {
            this.logger.error(`Session 重生失败: ${String(err)}`);
            return res.status(500).send('Login error');
        }
      } else {
        // Failure
        attempt.count++;
        attempt.lastAttempt = now;
        this.loginAttempts.set(ip, attempt);
        
        const safeUsername = String(username).substring(0, 50); // Limit log length
        this.logger.warn(`用户 '${safeUsername}' 从 ${ip} 登录失败。失败尝试次数: ${attempt.count}`);
        return res.status(401).send('Invalid username or password. <a href="/admin">Try again</a>');
      }
    });

    this.app.get('/logout', (req, res) => {
        return req.session.destroy((err) => {
            if (err) {
                this.logger.error(`销毁 Session 失败: ${err}`);
                return res.status(500).send('Could not log out.');
            }
            return res.redirect('/');
        });
    });

    this.app.get('/check-auth', (req, res) => {
        const isAdmin = (req.session as AdminSession).isAdmin ?? false;
        return res.json({ isAdmin });
    });

    this.app.get('/api/all-players', this.adminAuth.bind(this), (_req, res) => {
        const allPlayers = this.protocolHandler.getAllSessions().map(p => ({
            ...p,
            isAdmin: this.config.adminPhiraId.includes(p.id),
            isOwner: this.config.ownerPhiraId.includes(p.id),
        }));
        return res.json(allPlayers);
    });

    this.app.post('/api/admin/server-message', this.adminAuth.bind(this), (req, res) => {
        const { roomId, content } = req.body;
        if (!roomId || !content) {
            return res.status(400).json({ error: 'Missing roomId or content' });
        }
        this.protocolHandler.sendServerMessage(roomId, "【系统】"+content);
        return res.json({ success: true });
    });

    this.app.post('/api/admin/broadcast', this.adminAuth.bind(this), (req, res) => {
        const { content, target } = req.body;
        if (!content) {
            return res.status(400).json({ error: 'Missing content' });
        }
        
        const targetIds = (target && target.startsWith('#')) 
            ? target.substring(1).split(',').map((id: string) => id.trim()) 
            : null;

        const rooms = this.roomManager.listRooms();
        let sentCount = 0;
        rooms.forEach(room => {
            if (!targetIds || targetIds.includes(room.id)) {
                this.protocolHandler.sendServerMessage(room.id, "【全服播报】" + content);
                sentCount++;
            }
        });
        
        return res.json({ success: true, roomCount: sentCount });
    });

    this.app.post('/api/admin/bulk-action', this.adminAuth.bind(this), (req, res) => {
        const { action, value, target } = req.body;
        const rooms = this.roomManager.listRooms();
        
        const targetIds = (target && target.startsWith('#')) 
            ? target.substring(1).split(',').map((id: string) => id.trim()) 
            : null;

        let count = 0;
        rooms.forEach(room => {
            if (targetIds && !targetIds.includes(room.id)) return;

            switch (action) {
                case 'close_all':
                    this.protocolHandler.closeRoomByAdmin(room.id);
                    count++;
                    break;
                case 'lock_all':
                    if (!room.locked) this.protocolHandler.toggleRoomLock(room.id);
                    count++;
                    break;
                case 'unlock_all':
                    if (room.locked) this.protocolHandler.toggleRoomLock(room.id);
                    count++;
                    break;
                case 'set_max_players':
                    if (value && !isNaN(Number(value))) {
                        this.protocolHandler.setRoomMaxPlayers(room.id, Number(value));
                        count++;
                    }
                    break;
            }
        });

        // Handle global non-room actions
        if (!targetIds) {
            if (action === 'disable_room_creation') {
                this.roomManager.setGlobalLocked(true);
                return res.json({ success: true });
            } else if (action === 'enable_room_creation') {
                this.roomManager.setGlobalLocked(false);
                return res.json({ success: true });
            }
        }

        return res.json({ success: true, affectedCount: count });
    });

    this.app.post('/api/admin/kick-player', this.adminAuth.bind(this), (req, res) => {
        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId' });
        }
        const success = this.protocolHandler.kickPlayer(Number(userId));
        return res.json({ success });
    });

    this.app.post('/api/admin/force-start', this.adminAuth.bind(this), (req, res) => {
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.forceStartGame(roomId);
        return res.json({ success });
    });

    this.app.post('/api/admin/toggle-lock', this.adminAuth.bind(this), (req, res) => {
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.toggleRoomLock(roomId);
        return res.json({ success });
    });

    this.app.post('/api/admin/set-max-players', this.adminAuth.bind(this), (req, res) => {
        const { roomId, maxPlayers } = req.body;
        if (!roomId || maxPlayers === undefined) {
            return res.status(400).json({ error: 'Missing roomId or maxPlayers' });
        }
        const success = this.protocolHandler.setRoomMaxPlayers(roomId, Number(maxPlayers));
        return res.json({ success });
    });

    this.app.post('/api/admin/close-room', this.adminAuth.bind(this), (req, res) => {
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.closeRoomByAdmin(roomId);
        return res.json({ success });
    });

    this.app.post('/api/admin/toggle-mode', this.adminAuth.bind(this), (req, res) => {
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.toggleRoomMode(roomId);
        return res.json({ success });
    });

    this.app.get('/api/admin/room-blacklist', this.adminAuth.bind(this), (req, res) => {
        const { roomId } = req.query;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const room = this.roomManager.getRoom(String(roomId));
        return res.json({ blacklist: room?.blacklist || [] });
    });

    this.app.post('/api/admin/set-room-blacklist', this.adminAuth.bind(this), async (req, res) => {
        const { roomId, userIds } = req.body;
        if (!roomId || !Array.isArray(userIds)) {
            return res.status(400).json({ error: 'Missing roomId or invalid userIds' });
        }
        const success = await this.protocolHandler.setRoomBlacklistByAdmin(roomId, userIds);
        return res.json({ success });
    });

    this.app.get('/api/admin/room-whitelist', this.adminAuth.bind(this), (req, res) => {
        const { roomId } = req.query;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const room = this.roomManager.getRoom(String(roomId));
        return res.json({ whitelist: room?.whitelist || [] });
    });

    this.app.post('/api/admin/set-room-whitelist', this.adminAuth.bind(this), async (req, res) => {
        const { roomId, userIds } = req.body;
        if (!roomId || !Array.isArray(userIds)) {
            return res.status(400).json({ error: 'Missing roomId or invalid userIds' });
        }
        const success = await this.protocolHandler.setRoomWhitelistByAdmin(roomId, userIds);
        return res.json({ success });
    });

    // Public Status API for external servers
    this.app.get('/api/status', (req, res) => {
        const isAdmin = (req.session as AdminSession).isAdmin ?? false;
        const rooms = this.roomManager.listRooms()
            .filter(room => {
                // Admin can see everything
                if (isAdmin) {
                    return true;
                }
                // Mode 1: Public Web Only (Whitelist)
                if (this.config.enablePubWeb) {
                  return room.id.startsWith(this.config.pubPrefix);
                }
                // Mode 2: Private Web Exclusion (Blacklist)
                if (this.config.enablePriWeb) {
                  return !room.id.startsWith(this.config.priPrefix);
                }
                // Default: Show all
                return true;
            })
            .map(room => {
                const players = Array.from(room.players.values()).map(p => ({
                    id: p.user.id,
                    name: p.user.name,
                }));

                return {
                    id: room.id,
                    name: room.name,
                    playerCount: room.players.size,
                    maxPlayers: room.maxPlayers,
                    state: {
                        ...room.state,
                        chartId: (room.state as any).chartId ?? room.selectedChart?.id ?? null,
                        chartName: room.selectedChart?.name ?? null,
                    },
                    locked: room.locked,
                    cycle: room.cycle,
                    players: players,
                };
            });

        const response = {
            serverName: this.config.serverName,
            onlinePlayers: this.protocolHandler.getSessionCount(),
            roomCount: rooms.length,
            rooms: rooms
        };

        res.json(response);
    });
  }

  public getInternalServer(): Server {
    return this.server;
  }

  public getSessionParser(): express.RequestHandler {
    return this.sessionParser;
  }

  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.listen(this.config.webPort, () => {
        this.logger.info(`HTTP 服务器已启动，端口：${this.config.webPort}`);
        resolve();
      });

      this.server.on('error', (error) => {
        this.logger.error(`HTTP 服务器错误: ${error}`);
        reject(error);
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => {
        this.logger.info('HTTP 服务器已停止');
        resolve();
      });
    });
  }
}