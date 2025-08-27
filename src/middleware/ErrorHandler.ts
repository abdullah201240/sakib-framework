import { Request, Response, NextFunction } from 'express';
import { ValidationError } from 'class-validator';
import { ValidationError as ExpressValidationError } from 'express-validator';
import { Logger } from '../services/Logger';

export class HttpError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends HttpError {
  constructor(errors: ValidationError[]) {
    super(400, 'Validation failed');
    this.details = this.formatValidationErrors(errors);
  }

  private formatValidationErrors(errors: ValidationError[]): any[] {
    return errors.map(error => ({
      property: error.property,
      value: error.value,
      constraints: error.constraints,
      children: error.children?.length ? this.formatValidationErrors(error.children) : undefined,
    }));
  }
}

export class UnauthorizedError extends HttpError {
  constructor(message = 'Unauthorized') {
    super(401, message);
  }
}

export class ForbiddenError extends HttpError {
  constructor(message = 'Forbidden') {
    super(403, message);
  }
}

export class NotFoundError extends HttpError {
  constructor(message = 'Resource not found') {
    super(404, message);
  }
}

export class InternalServerError extends HttpError {
  constructor(message = 'Internal server error') {
    super(500, message);
  }
}

export class ErrorHandler {
  private static logger = new Logger();

  public static handle(
    err: Error | HttpError,
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    // Log the error
    ErrorHandler.logger.error(err.message, {
      error: err,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      path: req.path,
      method: req.method,
      body: req.body,
      query: req.query,
      params: req.params,
    });

    // Handle specific error types
    if (err instanceof HttpError) {
      res.status(err.statusCode).json({
        status: 'error',
        message: err.message,
        details: err.details,
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
      });
    } 
    // Handle class-validator validation errors
    else if (Array.isArray(err) && err[0] instanceof ValidationError) {
      const validationError = new ValidationError(err);
      res.status(validationError.statusCode).json({
        status: 'error',
        message: validationError.message,
        details: validationError.details,
      });
    }
    // Handle express-validator validation errors
    else if (Array.isArray(err) && err[0] instanceof ExpressValidationError) {
      res.status(400).json({
        status: 'error',
        message: 'Validation failed',
        details: err.map(e => ({
          param: e.param,
          msg: e.msg,
          location: e.location,
          value: e.value,
        })),
      });
    }
    // Handle JWT errors
    else if (err.name === 'JsonWebTokenError') {
      res.status(401).json({
        status: 'error',
        message: 'Invalid token',
      });
    } 
    // Handle token expiration
    else if (err.name === 'TokenExpiredError') {
      res.status(401).json({
        status: 'error',
        message: 'Token expired',
      });
    }
    // Handle database errors
    else if (err.name === 'MongoError' || err.name === 'MongoServerError') {
      const statusCode = 500;
      let message = 'Database error';
      
      // Handle duplicate key errors
      if ('code' in err && err.code === 11000) {
        message = 'Duplicate key error';
      }
      
      res.status(statusCode).json({
        status: 'error',
        message,
        ...(process.env.NODE_ENV === 'development' && { details: err.message }),
      });
    }
    // Default error handler
    else {
      const statusCode = 500;
      const message = process.env.NODE_ENV === 'production' 
        ? 'Internal server error' 
        : err.message;
      
      res.status(statusCode).json({
        status: 'error',
        message,
        ...(process.env.NODE_ENV === 'development' && { 
          details: err.message,
          stack: err.stack,
        }),
      });
    }
  }

  // Helper to create a 404 handler
  public static notFoundHandler(req: Request, res: Response): void {
    throw new NotFoundError(`Cannot ${req.method} ${req.path}`);
  }

  // Helper to create an async error handler
  public static catchAsync(fn: Function) {
    return (req: Request, res: Response, next: NextFunction) => {
      Promise.resolve(fn(req, res, next)).catch(err => next(err));
    };
  }
}
