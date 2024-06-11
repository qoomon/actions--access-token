import pino from 'pino'
import 'pino-pretty'
import process from 'process'

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({level: label.toUpperCase()}),
  },
  transport: process.env.LOG_PRETTY !== 'true' ? undefined : {
    target: 'pino-pretty', options: {
      sync: true,
      colorize: true,
      colorizeObjects: true,
    },
  },
})

export {logger as default}
