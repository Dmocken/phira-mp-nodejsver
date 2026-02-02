/*
 * MIT License
 * Copyright (c) 2024
 */

import { ConfigService, ServerConfig } from './config/config';
import { ConsoleLogger, Logger } from './logging/logger';
import { InMemoryRoomManager, RoomManager } from './domain/rooms/RoomManager';
import { PhiraAuthService } from './domain/auth/AuthService';
import { ProtocolHandler } from './domain/protocol/ProtocolHandler';
import { NetworkServer } from './network/NetworkServer';
import { HttpServer } from './network/HttpServer';
import { WebSocketServer } from './network/WebSocketServer';

export interface Application {
  readonly config: ServerConfig;
  readonly logger: Logger;
  readonly roomManager: RoomManager;
  start(): Promise<void>;
  stop(): Promise<void>;
  getTcpServer(): NetworkServer;
  getHttpServer(): HttpServer;
}

export const createApplication = (overrides?: Partial<ServerConfig>): Application => {
  const configService = new ConfigService(overrides);
  const config = configService.getConfig();
  const logLevel = config.logging.level;

  const logger = new ConsoleLogger('程序', logLevel);
  const roomLogger = new ConsoleLogger('房间', logLevel);
  const authLogger = new ConsoleLogger('认证', logLevel);
  const protocolLogger = new ConsoleLogger('协议', logLevel);
  const webSocketLogger = new ConsoleLogger('WebSocket', logLevel);

  let webSocketServer: WebSocketServer;

  const broadcastRooms = () => {
    if (webSocketServer) {
      webSocketServer.broadcastRooms();
    }
  };

  const broadcastStats = () => {
    if (webSocketServer) {
      webSocketServer.broadcastStats();
    }
  };

  const roomManager = new InMemoryRoomManager(roomLogger, config.roomSize, broadcastRooms);
  const authService = new PhiraAuthService(config.phiraApiUrl, authLogger);
  const protocolHandler = new ProtocolHandler(roomManager, authService, protocolLogger, config.serverName, broadcastStats);
  
  const networkServer = new NetworkServer(config, logger, protocolHandler);
  const httpServer = new HttpServer(
    {
      webPort: config.webPort,
      sessionSecret: config.sessionSecret,
      adminName: config.adminName,
      adminPassword: config.adminPassword,
    },
    logger,
    roomManager,
    protocolHandler,
  );
  webSocketServer = new WebSocketServer(httpServer.getInternalServer(), roomManager, protocolHandler, webSocketLogger);

  const start = async (): Promise<void> => {
    await Promise.all([
      httpServer.start(),
      networkServer.start(),
    ]);
  };

  const stop = async (): Promise<void> => {
    await Promise.all([
      httpServer.stop(),
      networkServer.stop(),
    ]);
  };

  return {
    config,
    logger,
    roomManager,
    start,
    stop,
    getTcpServer: () => networkServer,
    getHttpServer: () => httpServer,
  };
};
