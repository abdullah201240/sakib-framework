import winston from 'winston';
import path from 'path';
import { TransformableInfo } from 'logform';
import { Config } from '../config';

const { combine, timestamp, printf, colorize, json } = winston.format;

const logFormat = printf(({ level, message, timestamp, ...meta }) => {
  return `${timestamp} [${level}]: ${message} ${
    Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
  }`;
});

export class Logger {
  private logger: winston.Logger;
  private config: Config;

  constructor(config: Config) {
    this.config = config;
    
    // Create logs directory if it doesn't exist
    if (this.config.logger?.file) {
      const logDir = path.dirname(this.config.logger.file.filename);
      require('fs').mkdirSync(logDir, { recursive: true });
    }

    const transports: winston.transport[] = [];
    
    // Console transport
    if (this.config.logger?.console !== false) {
      transports.push(
        new winston.transports.Console({
          format: combine(
            colorize({ all: true }),
            timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            logFormat
          ),
        })
      );
    }

    // File transport
    if (this.config.logger?.file) {
      transports.push(
        new winston.transports.File({
          filename: this.config.logger.file.filename,
          maxsize: this.parseFileSize(this.config.logger.file.maxSize || '20m'),
          maxFiles: this.parseFileRetention(this.config.logger.file.maxFiles || '14d'),
          format: combine(timestamp(), json()),
        })
      );
    }

    this.logger = winston.createLogger({
      level: this.config.logger?.level || 'info',
      format: winston.format.combine(
        winston.format.errors({ stack: true }),
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports,
      exitOnError: false,
    });
  }

  // Get a writable stream for morgan
  public get stream() {
    return {
      write: (message: string) => {
        this.logger.info(message.trim());
      },
    };
  }

  public info(message: string, meta?: any): void {
    this.logger.info(message, meta);
  }

  public error(message: string, meta?: any): void {
    this.logger.error(message, meta);
  }

  public warn(message: string, meta?: any): void {
    this.logger.warn(message, meta);
  }

  public debug(message: string, meta?: any): void {
    this.logger.debug(message, meta);
  }

  public log(level: string, message: string, meta?: any): void {
    this.logger.log(level, message, meta);
  }

  // Helper to parse file size (e.g., '20m' -> 20 * 1024 * 1024)
  private parseFileSize(size: string): number {
    const match = size.match(/^(\d+)([kmg])b?$/i);
    if (!match) return 20 * 1024 * 1024; // Default 20MB

    const num = parseInt(match[1], 10);
    const unit = match[2].toLowerCase();

    switch (unit) {
      case 'k':
        return num * 1024;
      case 'm':
        return num * 1024 * 1024;
      case 'g':
        return num * 1024 * 1024 * 1024;
      default:
        return num;
    }
  }

  // Helper to parse file retention (e.g., '14d' -> 14)
  private parseFileRetention(retention: string): number {
    const match = retention.match(/^(\d+)([dmy])$/i);
    if (!match) return 14; // Default 14 days
    return parseInt(match[1], 10);
  }
}
