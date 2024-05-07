import type {InputOptions} from '@actions/core'
import * as core from '@actions/core'
import * as YAML from 'yaml'
import {HttpClientError} from '@actions/http-client'

/**
 * Run action and catch errors
 * @param action - action to run
 * @returns void
 */
export function runAction(action: () => Promise<void>): void {
  action().catch(async (error: unknown) => {
    console.error('Error:', error)
    let failedMessage = 'Unhandled error, see job logs'
    if (error != null && typeof error === 'object' && 'message' in error && typeof error.message === 'string') {
      failedMessage = error.message
    }
    core.setFailed(failedMessage)
  })
}

/**
 * Gets the yaml value of an input.
 * Unless trimWhitespace is set to false in InputOptions, the value is also trimmed.
 * Returns null if the value is not defined.
 *
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   parsed input as object
 */
export function getYamlInput(name: string, options?: InputOptions): unknown | undefined {
  const input = getInput(name, options)
  if (input === undefined) return
  return YAML.parse(input)
}

/**
 * Get input value
 * @param     name     name of the input to get
 * @param     options  optional. See InputOptions.
 * @returns   input value
 */
export function getInput(name: string, options?: InputOptions): string | undefined {
  return core.getInput(name, options) || undefined
}
