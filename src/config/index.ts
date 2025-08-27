import { CorsOptions } from 'cors';
import { RateLimitRequestHandler } from 'express-rate-limit';

export interface RateLimitConfig {
  windowMs: number;
  max: number;
  standardHeaders?: boolean;
  legacyHeaders?: boolean;
  message?: string | object;
  statusCode?: number;
  handler?: RateLimitRequestHandler;
}

export interface LoggerConfig {
  level?: string;
  format?: string;
  file?: {
    filename: string;
    maxSize?: string;
    maxFiles?: string;
  };
  console?: boolean;
}

export interface DatabaseConfig {
  type: 'mysql' | 'postgres' | 'sqlite' | 'mariadb' | 'mssql' | 'mongodb';
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
  synchronize: boolean;
  logging: boolean;
  entities: string[];
  migrations: string[];
  subscribers: string[];
  cli?: {
    entitiesDir: string;
    migrationsDir: string;
    subscribersDir: string;
  };
}

export interface AuthConfig {
  jwtSecret: string;
  jwtExpiresIn: string;
  refreshTokenExpiresIn: string;
  passwordSaltRounds: number;
}

export interface Config {
  port: number;
  environment: 'development' | 'production' | 'test';
  cors: CorsOptions;
  rateLimit: RateLimitConfig;
  logger?: LoggerConfig;
  database?: DatabaseConfig;
  auth?: AuthConfig;
  [key: string]: any;
}

export const defaultConfig: Partial<Config> = {
  port: 3000,
  environment: 'development',
  cors: {
    origin: '*', // In production, replace with your frontend domain
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
  },
  logger: {
    level: 'info',
    format: 'combined',
    console: true,
    file: {
      filename: 'logs/application.log',
      maxSize: '20m',
      maxFiles: '14d',
    },
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    jwtExpiresIn: '1h', // 1 hour
    refreshTokenExpiresIn: '7d', // 7 days
    passwordSaltRounds: 10,
  },
};
