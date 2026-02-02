
import express from 'express';
import { createServer, Server } from 'http';
import path from 'path';
import session, { SessionData } from 'express-session';
import { Logger } from '../logging/logger';
import { ServerConfig } from '../config/config';
import { RoomManager } from '../domain/rooms/RoomManager';
import { ProtocolHandler } from '../domain/protocol/ProtocolHandler';

interface AdminSession extends SessionData {
  isAdmin?: boolean;
}

export class HttpServer {
  private readonly app: express.Application;
  private readonly server: Server;
  private readonly config: Pick<ServerConfig, 'webPort' | 'sessionSecret' | 'adminName' | 'adminPassword'>;

  constructor(
    config: Pick<ServerConfig, 'webPort' | 'sessionSecret' | 'adminName' | 'adminPassword'>, 
    private readonly logger: Logger,
    private readonly roomManager: RoomManager,
    private readonly protocolHandler: ProtocolHandler,
  ) {
    this.config = config;
    this.app = express();
    this.server = createServer(this.app);
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    // Body parser for form data
    this.app.use(express.urlencoded({ extended: true }));

    // Session management
    this.app.use(session({
      secret: this.config.sessionSecret,
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false } // Note: Set to true if using HTTPS
    }));
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

    this.app.post('/login', (req, res) => {
      const { username, password } = req.body;
      if (username === this.config.adminName && password === this.config.adminPassword) {
        (req.session as AdminSession).isAdmin = true;
        this.logger.info(`Admin user '${username}' logged in successfully.`);
        return res.redirect('/');
      } else {
        this.logger.warn(`Failed login attempt for user '${username}'.`);
        // TODO: Pass error message to a login page with an error display
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
        const allPlayers = this.protocolHandler.getAllSessions();
        return res.json(allPlayers);
    });
  }

  public getInternalServer(): Server {
    return this.server;
  }

  public start(): Promise<void> {
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
