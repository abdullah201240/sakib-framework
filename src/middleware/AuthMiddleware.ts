import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { getRepository } from 'typeorm';
import { User } from '../entities/User';
import { UnauthorizedError, ForbiddenError } from './ErrorHandler';
import { Config } from '../config';

declare global {
  namespace Express {
    interface Request {
      user?: User;
      token?: string;
    }
  }
}

export class AuthMiddleware {
  private static config: Config;

  public static initialize(config: Config): void {
    AuthMiddleware.config = config;
  }

  public static authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const token = AuthMiddleware.extractToken(req);
      
      if (!token) {
        throw new UnauthorizedError('No authentication token provided');
      }

      const decoded = jwt.verify(token, AuthMiddleware.config.auth?.jwtSecret || '') as { id: string };
      
      const userRepository = getRepository(User);
      const user = await userRepository.findOne({ where: { id: decoded.id } });
      
      if (!user) {
        throw new UnauthorizedError('User not found');
      }

      // Attach user and token to the request object
      req.user = user;
      req.token = token;
      
      next();
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        next(new UnauthorizedError('Token has expired'));
      } else if (error instanceof jwt.JsonWebTokenError) {
        next(new UnauthorizedError('Invalid token'));
      } else {
        next(error);
      }
    }
  };

  public static authorize = (...roles: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      if (roles.length && !roles.includes(req.user.role)) {
        throw new ForbiddenError('Insufficient permissions');
      }

      next();
    };
  };

  private static extractToken(req: Request): string | null {
    // Get token from header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      return req.headers.authorization.split(' ')[1];
    }

    // Get token from cookies
    if (req.cookies && req.cookies.token) {
      return req.cookies.token;
    }

    // Get token from query parameters
    if (req.query && typeof req.query.token === 'string') {
      return req.query.token;
    }

    return null;
  }

  // Generate JWT token
  public static generateToken(user: User): string {
    return jwt.sign(
      { id: user.id, role: user.role },
      AuthMiddleware.config.auth?.jwtSecret || '',
      { expiresIn: AuthMiddleware.config.auth?.jwtExpiresIn || '1h' }
    );
  }

  // Generate refresh token
  public static generateRefreshToken(user: User): string {
    if (!AuthMiddleware.config.auth?.jwtSecret) {
      throw new Error('JWT secret is not configured');
    }
    
    return jwt.sign(
      { id: user.id },
      AuthMiddleware.config.auth.jwtSecret + '_refresh',
      { 
        expiresIn: AuthMiddleware.config.auth.refreshTokenExpiresIn || '7d',
        algorithm: 'HS256'
      }
    );
  }

  // Verify refresh token
  public static verifyRefreshToken(token: string): { id: string } | null {
    try {
      return jwt.verify(
        token,
        AuthMiddleware.config.auth?.jwtSecret + '_refresh'
      ) as { id: string };
    } catch (error) {
      return null;
    }
  }

  // Hash password
  public static async hashPassword(password: string): Promise<string> {
    const bcrypt = await import('bcryptjs');
    const salt = await bcrypt.genSalt(AuthMiddleware.config.auth?.passwordSaltRounds || 10);
    return await bcrypt.hash(password, salt);
  }

  // Compare password
  public static async comparePassword(password: string, hashedPassword: string): Promise<boolean> {
    const bcrypt = await import('bcryptjs');
    return await bcrypt.compare(password, hashedPassword);
  }
}
