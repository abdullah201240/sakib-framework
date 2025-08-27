// expresspro/index.js - Main framework entry point
const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Auth, AuthUtils } = require('./auth');

class SakibFramework {
  constructor() {
    this.app = express();
    this.middlewares = [];
    this.routes = [];
    this.models = {};
    this.controllers = {};
    this.services = {};
    this.auth = new Auth();
    this.authUtils = new AuthUtils();
    this.config = {};
    
    // Default settings
    this.settings = {
      env: process.env.NODE_ENV || 'development',
      port: process.env.PORT || 3000,
      views: path.join(process.cwd(), 'views'),
      public: path.join(process.cwd(), 'public')
    };
  }

  // Initialize the framework with configuration
  init(config = {}) {
    this.config = { ...this.settings, ...config };
    this._setup();
    return this;
  }

  // Setup core components
  _setup() {
    this._loadEnvironment();
    this._setupExpress();
    this._loadMiddlewares();
    this._loadRoutes();
    this._loadModels();
    this._loadControllers();
    this._loadServices();
    this._setupErrorHandling();
  }

  // Load environment variables
  _loadEnvironment() {
    const envPath = path.join(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      require('dotenv').config({ path: envPath });
    }
  }

  // Configure Express application
  _setupExpress() {
    this.app.set('env', this.config.env);
    this.app.set('port', this.config.port);
    this.app.set('views', this.config.views);
    this.app.set('view engine', 'ejs');
    this.app.use(express.static(this.config.public));
    
    // Built-in middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(compression());
    this.app.use(helmet());
    this.app.use(cors());
    
    if (this.config.env === 'development') {
      this.app.use(morgan('dev'));
    }
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100 // limit each IP to 100 requests per windowMs
    });
    this.app.use(limiter);
  }

  // Load custom middlewares
  _loadMiddlewares() {
    const middlewaresPath = path.join(process.cwd(), 'app', 'middlewares');
    if (fs.existsSync(middlewaresPath)) {
      fs.readdirSync(middlewaresPath).forEach(file => {
        if (path.extname(file) === '.js') {
          const middleware = require(path.join(middlewaresPath, file));
          this.app.use(middleware);
          this.middlewares.push(middleware);
        }
      });
    }
  }

  // Load routes automatically
  _loadRoutes() {
    const routesPath = path.join(process.cwd(), 'app', 'routes');
    if (fs.existsSync(routesPath)) {
      fs.readdirSync(routesPath).forEach(file => {
        if (path.extname(file) === '.js') {
          const route = require(path.join(routesPath, file));
          const routePath = `/${file === 'index.js' ? '' : file.replace('.js', '')}`;
          this.app.use(routePath, route);
          this.routes.push({ path: routePath, handler: route });
        }
      });
    }
  }

  // Load models
  _loadModels() {
    const modelsPath = path.join(process.cwd(), 'app', 'models');
    if (fs.existsSync(modelsPath)) {
      fs.readdirSync(modelsPath).forEach(file => {
        if (path.extname(file) === '.js') {
          const modelName = path.basename(file, '.js');
          this.models[modelName] = require(path.join(modelsPath, file));
        }
      });
    }
  }

  // Load controllers
  _loadControllers() {
    const controllersPath = path.join(process.cwd(), 'app', 'controllers');
    if (fs.existsSync(controllersPath)) {
      fs.readdirSync(controllersPath).forEach(file => {
        if (path.extname(file) === '.js') {
          const controllerName = path.basename(file, '.js');
          this.controllers[controllerName] = require(path.join(controllersPath, file));
        }
      });
    }
  }

  // Load services
  _loadServices() {
    const servicesPath = path.join(process.cwd(), 'app', 'services');
    if (fs.existsSync(servicesPath)) {
      fs.readdirSync(servicesPath).forEach(file => {
        if (path.extname(file) === '.js') {
          const serviceName = path.basename(file, '.js');
          this.services[serviceName] = require(path.join(servicesPath, file));
        }
      });
    }
  }

  // Enhanced error handling
  _setupErrorHandling() {
    // 404 handler
    this.app.use((req, res, next) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.method} ${req.url} not found`
      });
    });

    // Global error handler
    this.app.use((err, req, res, next) => {
      console.error(err.stack);
      
      const statusCode = err.status || err.statusCode || 500;
      res.status(statusCode).json({
        error: statusCode === 500 ? 'Internal Server Error' : err.message,
        ...(this.config.env === 'development' && { stack: err.stack })
      });
    });
  }

  // Add a new middleware
  use(middleware) {
    this.app.use(middleware);
    this.middlewares.push(middleware);
    return this;
  }

  // Add a new route
  addRoute(path, router) {
    this.app.use(path, router);
    this.routes.push({ path, handler: router });
    return this;
  }

  // Start the server
  start(callback) {
    const server = this.app.listen(this.config.port, () => {
      console.log(`ExpressPro server running in ${this.config.env} mode on port ${this.config.port}`);
      if (callback) callback(server);
    });
    return server;
  }

  // Get the Express app instance
  getApp() {
    return this.app;
  }
}

// Enhanced Router with validation
class SakibFrameworkRouter {
  constructor() {
    this.router = express.Router();
    this.routes = [];
    this.auth = new Auth();
    this.authUtils = new AuthUtils();
  }

  // GET method with optional validation
  get(path, handler, validation = null) {
    const route = { method: 'GET', path, handler, validation };
    this.routes.push(route);
    
    if (validation) {
      this.router.get(path, validation, handler);
    } else {
      this.router.get(path, handler);
    }
    return this;
  }

  // POST method with optional validation
  post(path, handler, validation = null) {
    const route = { method: 'POST', path, handler, validation };
    this.routes.push(route);
    
    if (validation) {
      this.router.post(path, validation, handler);
    } else {
      this.router.post(path, handler);
    }
    return this;
  }

  // PUT method with optional validation
  put(path, handler, validation = null) {
    const route = { method: 'PUT', path, handler, validation };
    this.routes.push(route);
    
    if (validation) {
      this.router.put(path, validation, handler);
    } else {
      this.router.put(path, handler);
    }
    return this;
  }

  // DELETE method with optional validation
  delete(path, handler, validation = null) {
    const route = { method: 'DELETE', path, handler, validation };
    this.routes.push(route);
    
    if (validation) {
      this.router.delete(path, validation, handler);
    } else {
      this.router.delete(path, handler);
    }
    return this;
  }

  // Add middleware to the router
  use(middleware) {
    this.router.use(middleware);
    return this;
  }

  // Get the express router
  getRouter() {
    return this.router;
  }

  // Get authentication instance
  getAuth() {
    return this.auth;
  }

  // Get authentication utilities
  getAuthUtils() {
  return this.authUtils;
}
};



// Response utilities
const Response = {
  success: (res, data, message = 'Success', statusCode = 200) => {
    res.status(statusCode).json({
      success: true,
      message,
      data
    });
  },
  
  error: (res, message = 'Error', statusCode = 500, details = null) => {
    const response = {
      success: false,
      message
    };
    
    if (details) {
      response.details = details;
    }
    
    res.status(statusCode).json(response);
  },
  
  paginate: (res, data, pagination, message = 'Success') => {
    res.status(200).json({
      success: true,
      message,
      data,
      pagination
    });
  }
};

// Database utilities
const Database = {
  connect: async (mongoose, uri) => {
    try {
      await mongoose.connect(uri || process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log('Connected to MongoDB');
    } catch (error) {
      console.error('MongoDB connection error:', error);
      process.exit(1);
    }
  },
  
  disconnect: async (mongoose) => {
    await mongoose.connection.close();
    console.log('Disconnected from MongoDB');
  }
};

// Export the framework
module.exports = {
  SakibFramework,
  SakibFrameworkRouter,
  Response,
  Database
};