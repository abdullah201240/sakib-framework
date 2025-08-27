import { Application } from './core/Application';
import { Config } from './config';

export * from './core/decorators';
export * from './core/interfaces';
export * from './core/services';
export * from './core/middleware';
export * from './core/entities';

export const createApp = (config: Partial<Config> = {}) => {
  return new Application(config);
};

export default createApp;
