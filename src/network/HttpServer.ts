
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
  private readonly blacklistFile = path.join(__dirname, '../../login_blacklist.log');
  
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
            this.logger.info(`Loaded ${this.blacklistedIps.size} blacklisted IPs from file.`);
        } catch (e) {
            this.logger.error('Failed to load blacklist file', { error: e });
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
        this.logger.error('Failed to write to blacklist log', { error: e });
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
        this.logger.info('Aliyun Captcha 2.0 client initialized');
      } catch (error) {
        this.logger.error('Failed to initialize Aliyun Captcha client', { error: String(error) });
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
              
              const outcome = await result.json();
              if (!outcome.success) {
                  this.logger.warn(`Turnstile verification failed for IP ${ip}`, outcome);
                  return { success: false, message: 'Turnstile verification failed. Please try again.' };
              }
              return { success: true };
          } catch (error) {
              this.logger.error('Turnstile verification error:', { error: String(error) });
              return { success: false, message: 'Internal server error during verification.' };
          }
      }

      if (provider === 'aliyun') {
          const captchaVerifyParam = req.body['captchaVerifyParam'] || req.body['captcha_verify_param'];
          if (!this.aliyunCaptchaClient || !this.config.aliyunCaptchaSceneId) {
              this.logger.error('Aliyun Captcha client not initialized or Scene ID missing');
              return { success: false, message: 'Captcha service configuration error.' };
          }
          if (!captchaVerifyParam) return { success: false, message: 'Aliyun Captcha verification failed (missing param).' };

          try {
              const verifyIntelligentCaptchaRequest = new $Captcha20230305.VerifyIntelligentCaptchaRequest({
                  captchaVerifyParam: captchaVerifyParam,
                  sceneId: this.config.aliyunCaptchaSceneId,
              });
              
              const response = await this.aliyunCaptchaClient.verifyIntelligentCaptcha(verifyIntelligentCaptchaRequest);
              
              this.logger.info(`Aliyun 2.0 API Response for IP ${ip}:`, { body: response.body });

              const verifyResult = response.body?.result?.verifyResult;
              if (response.body && response.body.result && (verifyResult === true || (verifyResult as any) === 'true')) {
                  this.logger.info(`Aliyun Captcha verified successfully for IP ${ip}`);
                  return { success: true };
              } else {
                  this.logger.warn(`Aliyun Captcha verification failed for IP ${ip}`, response.body);
                  let msg = response.body?.message || 'Verification failed';
                  if (response.body?.result?.verifyCode === 'F023') {
                      msg = 'SceneId mismatch (F023). Please check your Aliyun console.';
                  }
                  return { success: false, message: msg };
              }
          } catch (error: any) {
              this.logger.error('Aliyun Captcha SDK error:', { 
                  message: error.message,
                  code: error.code,
                  data: error.data,
                  stack: error.stack
              });
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
        this.logger.warn('SECURITY WARNING: Using default session secret. Please set SESSION_SECRET in .env file.');
    }

    this.app.use(this.sessionParser);
    
    // CORS middleware to allow other servers to fetch data
    this.app.use((_req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*'); // Allow any server to request
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
        next();
    });
  }

  private setupRoutes(): void {
    const publicPath = path.join(__dirname, '../../public');
    this.app.use(express.static(publicPath));
    this.logger.info(`Serving static files from ${publicPath}`);

    this.app.get('/admin', (req, res) => {
      if ((req.session as AdminSession).isAdmin) {
        return res.redirect('/');
      }
      res.sendFile(path.join(publicPath, 'admin.html'));
    });

    this.app.get('/api/config/public', (_req, res) => {
        res.json({
            turnstileSiteKey: this.config.turnstileSiteKey,
            captchaProvider: this.config.captchaProvider,
            aliyunCaptchaSceneId: this.config.aliyunCaptchaSceneId,
            aliyunCaptchaPrefix: this.config.aliyunCaptchaPrefix,
        });
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
            this.logger.info(`Admin user '${safeUsername}' logged in successfully from ${ip}.`);
            return res.redirect('/');
        } catch (err) {
            this.logger.error('Session regeneration failed', { error: String(err) });
            return res.status(500).send('Login error');
        }
      } else {
        // Failure
        attempt.count++;
        attempt.lastAttempt = now;
        this.loginAttempts.set(ip, attempt);
        
        const safeUsername = String(username).substring(0, 50); // Limit log length
        this.logger.warn(`Failed login attempt for user '${safeUsername}' from ${ip}. Failed attempts: ${attempt.count}`);
        return res.status(401).send('Invalid username or password. <a href="/admin">Try again</a>');
      }
    });

    this.app.get('/logout', (req, res) => {
        return req.session.destroy((err) => {
            if (err) {
                this.logger.error('Failed to destroy session:', err);
                return res.status(500).send('Could not log out.');
            }
            return res.redirect('/');
        });
    });

    this.app.get('/check-auth', (req, res) => {
        const isAdmin = (req.session as AdminSession).isAdmin ?? false;
        return res.json({ isAdmin });
    });

    this.app.get('/api/all-players', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const allPlayers = this.protocolHandler.getAllSessions().map(p => ({
            ...p,
            isAdmin: this.config.adminPhiraId.includes(p.id),
            isOwner: this.config.ownerPhiraId.includes(p.id),
        }));
        return res.json(allPlayers);
    });

    this.app.post('/api/admin/server-message', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId, content } = req.body;
        if (!roomId || !content) {
            return res.status(400).json({ error: 'Missing roomId or content' });
        }
        this.protocolHandler.sendServerMessage(roomId, "【系统】"+content);
        return res.json({ success: true });
    });

    this.app.post('/api/admin/broadcast', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
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

    this.app.post('/api/admin/bulk-action', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
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

    this.app.post('/api/admin/kick-player', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { userId } = req.body;
        if (!userId) {
            return res.status(400).json({ error: 'Missing userId' });
        }
        const success = this.protocolHandler.kickPlayer(Number(userId));
        return res.json({ success });
    });

    this.app.post('/api/admin/force-start', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.forceStartGame(roomId);
        return res.json({ success });
    });

    this.app.post('/api/admin/toggle-lock', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.toggleRoomLock(roomId);
        return res.json({ success });
    });

    this.app.post('/api/admin/set-max-players', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId, maxPlayers } = req.body;
        if (!roomId || maxPlayers === undefined) {
            return res.status(400).json({ error: 'Missing roomId or maxPlayers' });
        }
        const success = this.protocolHandler.setRoomMaxPlayers(roomId, Number(maxPlayers));
        return res.json({ success });
    });

    this.app.post('/api/admin/close-room', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.closeRoomByAdmin(roomId);
        return res.json({ success });
    });

    this.app.post('/api/admin/toggle-mode', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId } = req.body;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const success = this.protocolHandler.toggleRoomMode(roomId);
        return res.json({ success });
    });

    this.app.get('/api/admin/room-blacklist', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId } = req.query;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const room = this.roomManager.getRoom(String(roomId));
        return res.json({ blacklist: room?.blacklist || [] });
    });

    this.app.post('/api/admin/set-room-blacklist', async (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId, userIds } = req.body;
        if (!roomId || !Array.isArray(userIds)) {
            return res.status(400).json({ error: 'Missing roomId or invalid userIds' });
        }
        const success = await this.protocolHandler.setRoomBlacklistByAdmin(roomId, userIds);
        return res.json({ success });
    });

    this.app.get('/api/admin/room-whitelist', (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const { roomId } = req.query;
        if (!roomId) {
            return res.status(400).json({ error: 'Missing roomId' });
        }
        const room = this.roomManager.getRoom(String(roomId));
        return res.json({ whitelist: room?.whitelist || [] });
    });

    this.app.post('/api/admin/set-room-whitelist', async (req, res) => {
        if (!(req.session as AdminSession).isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
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
        this.logger.info(`HTTP server listening on port ${this.config.webPort}`);
        resolve();
      });

      this.server.on('error', (error) => {
        this.logger.error('HTTP server error:', { error });
        reject(error);
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => {
        this.logger.info('HTTP server stopped');
        resolve();
      });
    });
  }
}
