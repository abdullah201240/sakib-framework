// expresspro/auth.js - Complete Authentication Module
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

class Auth {
  constructor(options = {}) {
    this.secret = options.secret || process.env.JWT_SECRET || 'fallback_secret_change_in_production';
    this.tokenExpiry = options.tokenExpiry || '7d';
    this.refreshTokenExpiry = options.refreshTokenExpiry || '30d';
    this.algorithm = options.algorithm || 'HS256';
    this.issuer = options.issuer || 'expresspro-app';
    this.audience = options.audience || 'expresspro-users';
    
    // In a production system, you'd use a database for these
    this.refreshTokens = new Map();
    this.passwordResetTokens = new Map();
  }

  // JWT-based authentication middleware
  authenticate = (req, res, next) => {
    const authHeader = req.header('Authorization');
    let token = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    } else if (req.query && req.query.token) {
      token = req.query.token;
    }

    if (!token) {
      return res.status(401).json({ 
        success: false,
        error: 'Access denied. No authentication token provided.' 
      });
    }

    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: [this.algorithm],
        issuer: this.issuer,
        audience: this.audience
      });
      
      req.user = decoded;
      next();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          success: false,
          error: 'Token expired',
          details: 'Please refresh your token or login again'
        });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid token',
          details: 'The provided token is malformed or invalid'
        });
      } else {
        return res.status(401).json({ 
          success: false,
          error: 'Authentication failed',
          details: error.message
        });
      }
    }
  };

  // Role-based authorization middleware
  authorize = (...roles) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ 
          success: false,
          error: 'Authentication required' 
        });
      }

      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ 
          success: false,
          error: 'Access denied',
          details: `Required roles: ${roles.join(', ')}. Your role: ${req.user.role}`
        });
      }

      next();
    };
  };

  // Permission-based authorization
  hasPermission = (permission) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ 
          success: false,
          error: 'Authentication required' 
        });
      }

      // In a real app, you'd check against user permissions from database
      const userPermissions = req.user.permissions || [];
      
      if (!userPermissions.includes(permission)) {
        return res.status(403).json({ 
          success: false,
          error: 'Insufficient permissions',
          details: `Required permission: ${permission}`
        });
      }

      next();
    };
  };

  // Generate JWT token
  generateToken = (payload, options = {}) => {
    const tokenOptions = {
      expiresIn: options.expiresIn || this.tokenExpiry,
      issuer: this.issuer,
      audience: this.audience,
      algorithm: this.algorithm
    };

    return jwt.sign(payload, this.secret, tokenOptions);
  };

  // Verify JWT token
  verifyToken = (token) => {
    try {
      return jwt.verify(token, this.secret, {
        algorithms: [this.algorithm],
        issuer: this.issuer,
        audience: this.audience
      });
    } catch (error) {
      throw error;
    }
  };

  // Generate refresh token
  generateRefreshToken = (userId) => {
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days from now
    
    // Store refresh token (in production, use database)
    this.refreshTokens.set(refreshToken, {
      userId,
      expiresAt,
      isValid: true
    });
    
    return refreshToken;
  };

  // Verify refresh token
  verifyRefreshToken = (refreshToken) => {
    const tokenData = this.refreshTokens.get(refreshToken);
    
    if (!tokenData) {
      throw new Error('Refresh token not found');
    }
    
    if (!tokenData.isValid) {
      throw new Error('Refresh token is no longer valid');
    }
    
    if (new Date() > tokenData.expiresAt) {
      this.refreshTokens.delete(refreshToken);
      throw new Error('Refresh token has expired');
    }
    
    return tokenData;
  };

  // Revoke refresh token
  revokeRefreshToken = (refreshToken) => {
    if (this.refreshTokens.has(refreshToken)) {
      this.refreshTokens.delete(refreshToken);
      return true;
    }
    return false;
  };

  // Revoke all refresh tokens for a user
  revokeAllUserRefreshTokens = (userId) => {
    let count = 0;
    for (const [token, data] of this.refreshTokens.entries()) {
      if (data.userId === userId) {
        this.refreshTokens.delete(token);
        count++;
      }
    }
    return count;
  };

  // Hash password
  hashPassword = async (password, saltRounds = 12) => {
    return await bcrypt.hash(password, saltRounds);
  };

  // Compare password with hash
  comparePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
  };

  // Generate password reset token
  generatePasswordResetToken = (userId) => {
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour from now
    
    // Store reset token (in production, use database)
    this.passwordResetTokens.set(resetToken, {
      userId,
      expiresAt,
      used: false
    });
    
    return resetToken;
  };

  // Verify password reset token
  verifyPasswordResetToken = (resetToken) => {
    const tokenData = this.passwordResetTokens.get(resetToken);
    
    if (!tokenData) {
      throw new Error('Password reset token not found');
    }
    
    if (tokenData.used) {
      throw new Error('Password reset token has already been used');
    }
    
    if (new Date() > tokenData.expiresAt) {
      this.passwordResetTokens.delete(resetToken);
      throw new Error('Password reset token has expired');
    }
    
    return tokenData;
  };

  // Mark password reset token as used
  markPasswordResetTokenAsUsed = (resetToken) => {
    if (this.passwordResetTokens.has(resetToken)) {
      const tokenData = this.passwordResetTokens.get(resetToken);
      tokenData.used = true;
      this.passwordResetTokens.set(resetToken, tokenData);
      return true;
    }
    return false;
  };

  // Generate email verification token
  generateEmailVerificationToken = (userId, email) => {
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1); // 1 day from now
    
    // In production, store in database with user record
    return {
      token: verificationToken,
      expiresAt
    };
  };

  // Middleware to require email verification
  requireVerifiedEmail = (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false,
        error: 'Authentication required' 
      });
    }

    if (!req.user.emailVerified) {
      return res.status(403).json({ 
        success: false,
        error: 'Email verification required',
        details: 'Please verify your email address to access this resource'
      });
    }

    next();
  };

  // Get token from request
  getTokenFromRequest = (req) => {
    const authHeader = req.header('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    } else if (req.cookies && req.cookies.accessToken) {
      return req.cookies.accessToken;
    } else if (req.query && req.query.token) {
      return req.query.token;
    }
    return null;
  };

  // Decode token without verification (for inspection)
  decodeToken = (token) => {
    return jwt.decode(token);
  };
}

// Auth utility functions
const AuthUtils = {
  // Password strength validator
  validatePasswordStrength: (password, options = {}) => {
    const {
      minLength = 8,
      requireUppercase = true,
      requireLowercase = true,
      requireNumbers = true,
      requireSpecialChars = true
    } = options;

    const errors = [];

    if (password.length < minLength) {
      errors.push(`Password must be at least ${minLength} characters long`);
    }

    if (requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  },

  // Generate random password
  generateRandomPassword: (length = 12) => {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }
    
    return password;
  },

  // Sanitize user input for authentication
  sanitizeAuthInput: (input) => {
    if (typeof input !== 'string') return '';
    
    // Remove leading/trailing whitespace
    let sanitized = input.trim();
    
    // Prevent NoSQL injection
    sanitized = sanitized.replace(/[${}<>\]]/g, '');
    
    // Prevent XSS
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    
    return sanitized;
  }
};

module.exports = { Auth, AuthUtils };