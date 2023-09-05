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
    core.setFailed('Unhandled error, see job logs')
    console.error('Error:', error)
    if (error instanceof HttpClientError) {
      console.error('Http response:', error.result)
    }
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
  const input = core.getInput(name, options)
  if (input === '') return
  return YAML.parse(input)
}
