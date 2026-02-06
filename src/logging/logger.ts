/*
 * MIT License
 * Copyright (c) 2024
 */

import * as fs from 'fs';
import * as path from 'path';

export type LogLevel = 'debug' | 'info' | 'mark' | 'warn' | 'error';

export interface LogMetadata {
  [key: string]: unknown;
}

export interface Logger {
  info(message: string, metadata?: LogMetadata): void;
  mark(message: string, metadata?: LogMetadata): void;
  warn(message: string, metadata?: LogMetadata): void;
  error(message: string, metadata?: LogMetadata): void;
  debug(message: string, metadata?: LogMetadata): void;
}

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  mark: 25,
  warn: 30,
  error: 40,
};

const COLOR_CODES: Record<string, string> = {
  RESET: '\x1b[0m',
  DEBUG: '\x1b[90m', // 灰色
  INFO: '\x1b[32m',  // 绿色
  MARK: '\x1b[36m',  // 青色
  WARN: '\x1b[33m',  // 黄色
  ERROR: '\x1b[31m', // 红色
};

const normaliseLevel = (level: string | undefined): LogLevel => {
  const candidate = level?.toLowerCase();
  if (candidate === 'debug' || candidate === 'info' || candidate === 'mark' || candidate === 'warn' || candidate === 'error') {
    return candidate;
  }

  return 'info';
};

export class ConsoleLogger implements Logger {
  private readonly minimumLevel: LogLevel;

  constructor(private readonly context: string = 'app', level: string | undefined = 'info') {
    this.minimumLevel = normaliseLevel(level);
    
    // Ensure logs directory exists
    const logDir = path.join(process.cwd(), 'logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  info(message: string, metadata: LogMetadata = {}): void {
    if (!this.shouldLog('info')) {
      return;
    }
    const formatted = this.formatMessage('INFO', message, metadata);
    console.info(formatted.console);
    this.writeToFile(formatted.file);
  }

  mark(message: string, metadata: LogMetadata = {}): void {
    if (!this.shouldLog('mark')) {
      return;
    }
    const formatted = this.formatMessage('MARK', message, metadata);
    console.info(formatted.console);
    this.writeToFile(formatted.file);
  }

  warn(message: string, metadata: LogMetadata = {}): void {
    if (!this.shouldLog('warn')) {
      return;
    }
    const formatted = this.formatMessage('WARN', message, metadata);
    console.warn(formatted.console);
    this.writeToFile(formatted.file);
  }

  error(message: string, metadata: LogMetadata = {}): void {
    if (!this.shouldLog('error')) {
      return;
    }
    const formatted = this.formatMessage('ERROR', message, metadata);
    console.error(formatted.console);
    this.writeToFile(formatted.file);
  }

  debug(message: string, metadata: LogMetadata = {}): void {
    if (!this.shouldLog('debug')) {
      return;
    }
    const formatted = this.formatMessage('DEBUG', message, metadata);
    console.debug(formatted.console);
    this.writeToFile(formatted.file);
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[this.minimumLevel];
  }

  private getLogFilePath(): string {
    const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    return path.join(process.cwd(), 'logs', `server-${date}.log`);
  }

  private writeToFile(line: string): void {
    try {
      const logFile = this.getLogFilePath();
      fs.appendFileSync(logFile, line + '\n');
    } catch (err) {
      console.error('Failed to write to log file:', err);
    }
  }

  private formatMessage(level: string, message: any, metadata: LogMetadata): { console: string; file: string } {
    const now = new Date();
    const timestamp = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}.${String(now.getMilliseconds()).padStart(3, '0')}`;
    
    let color = COLOR_CODES.RESET;
    if (level === 'DEBUG') color = COLOR_CODES.DEBUG;
    else if (level === 'INFO') color = COLOR_CODES.INFO;
    else if (level === 'MARK') color = COLOR_CODES.MARK;
    else if (level === 'WARN') color = COLOR_CODES.WARN;
    else if (level === 'ERROR') color = COLOR_CODES.ERROR;

    let msgStr = '';
    if (
      message === undefined ||
      message === null ||
      (typeof message === 'string' && message.trim() === '') ||
      (typeof message === 'object' && Object.keys(message).length === 0)
    ) {
      msgStr = '';
    } else if (typeof message === 'object') {
      msgStr = JSON.stringify(message);
    } else {
      msgStr = message;
    }

    const metaStr = metadata && Object.keys(metadata).length > 0 ? ' ' + JSON.stringify(metadata) : '';
    
    return {
      console: `[${timestamp}] ${color}[${level}] ${msgStr}${metaStr}${COLOR_CODES.RESET}`,
      file: `[${timestamp}] [${level}] ${msgStr}${metaStr}`
    };
  }
}