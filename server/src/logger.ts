import pino from 'pino';
import process from 'process';

const logger = pino({
  level: process.env.LOG_LEVEL?.toLowerCase() || 'info',
  formatters: {
    level: (label:string) => ({level: label.toUpperCase()}),
  },
});

export {logger};
