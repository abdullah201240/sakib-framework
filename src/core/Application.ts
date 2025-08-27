import express, { Application as ExpressApplication, Request, Response, NextFunction } from 'express';
import { Server } from 'http';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { Config } from '../config';
import { Logger } from '../services/Logger';
import { ErrorHandler } from '../middleware/ErrorHandler';

export class Application {
  private app: ExpressApplication;
  private server: Server | null = null;
  private config: Config;
  private logger: Logger;

  constructor(config: Partial<Config> = {}) {
    this.config = this.initializeConfig(config);
    this.logger = new Logger(this.config);
    this.app = express();
    
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeConfig(config: Partial<Config>): Config {
    const validEnvironments = ['development', 'production', 'test'] as const;
    type Environment = typeof validEnvironments[number];
    
    const env = config.environment || process.env.NODE_ENV;
    const environment = validEnvironments.includes(env as Environment) 
      ? env as Environment 
      : 'development';

    return {
      port: config.port || parseInt(process.env.PORT || '3000', 10),
      environment,
      cors: config.cors || {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true,
      },
      rateLimit: config.rateLimit || {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
      },
      ...config,
    };
  }

  private initializeMiddlewares(): void {
    // Security headers
    this.app.use(helmet());
    
    // CORS
    this.app.use(cors(this.config.cors));
    
    // Request logging
    if (this.config.environment !== 'test') {
      this.app.use(morgan('combined', { stream: this.logger.stream }));
    }
    
    // Rate limiting
    if (this.config.rateLimit) {
      this.app.use(rateLimit(this.config.rateLimit));
    }
    
    // Body parsing
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    
    // Response compression
    this.app.use(compression());
  }

  private initializeRoutes(): void {
    // Health check endpoint
    this.app.get('/health', (req: Request, res: Response) => {
      res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
    });
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use((req: Request, res: Response) => {
      res.status(404).json({
        status: 'error',
        message: 'Not Found',
        path: req.path,
      });
    });

    // Global error handler
    this.app.use(ErrorHandler.handle);
  }

  public getApp(): ExpressApplication {
    return this.app;
  }

  public async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = this.app.listen(this.config.port, () => {
        this.logger.info(`Server is running on port ${this.config.port}`);
        resolve();
      });
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.server) {
        this.server.close((err) => {
          if (err) {
            this.logger.error('Error stopping server:', err);
            return reject(err);
          }
          this.logger.info('Server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  public getConfig(): Config {
    return { ...this.config };
  }
}
