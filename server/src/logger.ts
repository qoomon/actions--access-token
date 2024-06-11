import pino from 'pino'
import 'pino-pretty'
import process from 'process'

const logger = pino({

  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label:string) => ({level: label.toUpperCase()}),
  },
  transport: process.env.LOG_PRETTY === 'true' ? {
    target: 'pino-pretty', options: {sync: true},
  } : undefined,
}, pino.destination({sync: true}))

export {logger as default}
