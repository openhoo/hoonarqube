import config from '../config/app';

export function boot() {
  return config.load();
}
