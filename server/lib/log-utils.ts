import {LogLevelNames} from 'loglevel'

/**
 * This function will return the log level of the given string
 * @param level - log level
 * @returns log level
 */
export function logLevelOf(level?: string): LogLevelNames | undefined {
  return ['trace', 'debug', 'info', 'warn', 'error'].includes(level?.toLowerCase() as LogLevelNames) ?
      (level?.toLowerCase() as LogLevelNames) :
      undefined
}
