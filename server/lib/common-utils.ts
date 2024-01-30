/**
 * This function returns true if the given object has entries
 * @param obj - object to check
 * @returns true if the given object has entries
 */
export function hasEntries<T extends object>(obj: T): boolean {
  return Object.entries(obj).length > 0
}

/**
 * This function will throw the given error
 * @param error - error to throw
 * @returns never
 */
export function _throw(error: unknown): never {
  throw error
}

/**
 * This function will ensure that the given object is not empty, otherwise it will throw an error
 * @param obj - object to check
 * @returns the given object
 */
export function ensureHasEntries<T extends object>(obj: T): T {
  if (!hasEntries(obj)) throw Error('Illegal argument, object can not be empty')
  return obj
}

/**
 * This function will return a new array with unique values
 * @param iterable - an iterable
 * @returns array with unique values
 */
export function unique<T>(iterable: Iterable<T>): T[] {
  return Array.from(new Set(iterable))
}

/**
 * This function will return a formatted string representation of the given array
 * Items will be separated by commas and the word 'and' for the last item
 * @param arr - array of strings
 * @returns formatted string
 */
export function formatArray(arr: string[]): string {
  if (arr.length === 0) return ''
  if (arr.length === 1) return arr[0]

  return arr.slice(0, arr.length - 1).join(', ') + ' and ' + arr[arr.length - 1]
}

/**
 * This function will transform an array to an array of tuples
 * @param iterable - an iterable
 * @returns array of tuples
 */
export function tuplesOf<T>(iterable: Iterable<T>): [T, T | undefined][] {
  const result: [T, T | undefined][] = []
  const iterator = iterable[Symbol.iterator]()
  let iteratorResult
  while (!(iteratorResult = iterator.next()).done) {
    result.push([
      iteratorResult.value,
      iterator.next().value,
    ])
  }
  return result
}

/**
 * This function will reduce an array of tuples to an object
 * @param iterable - an iterable
 * @returns an object
 */
export function objectOfTuples<T>(iterable: Iterable<[T, T | undefined]>): Record<string, T | undefined> {
  const result: Record<string, T | undefined> = {}
  for (const [key, value] of iterable) {
    result[String(key)] = value
  }
  return result
}

/**
 * This function will create a regular expression from a wildcard pattern
 * @param pattern - wildcard pattern
 * @param flags - regular expression flags
 * @returns regular expression
 */
export function regexpOfWildcardPattern(pattern: string, flags?: string): RegExp {
  const regexp = escapeRegexp(pattern)
      .replace(/\\\*/g, '.+') // replace * with match one or more characters
      .replace(/\\\?/g, '.') // replace ? with match one characters
  return RegExp(`^${regexp}$`, flags)

  /**
   * Escape regular expression special characters
   * @param string - string to escape
   * @returns escaped string
   */
  function escapeRegexp(string: string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }
}

/**
 * This function will return a new object created from mapped entries of the given object
 * @param object - an object
 * @param fn - mapping function
 * @returns new mapped object
 */
export function mapObject<V, U>(
    object: Record<string, V>,
    fn: (entry: [string, V]) => [string, U],
): Record<string, U> {
  return Object.fromEntries(Object.entries(object).map(fn)) as Record<string, U>
}

/**
 * This function will return a promise that will resolve after the given time
 * @param ms - time in milliseconds
 * @returns promise
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * This function wraps the given function in a promise
 * @param func - function to wrap
 * @returns promise
 */
export async function promise<T>(func: () => T): Promise<T> {
  return new Promise((resolve, reject) => {
    try {
      resolve(func())
    } catch (error: unknown) {
      reject(error)
    }
  })
}

/**
 * Indent string
 * @param string - string to indent
 * @param indent - indent string
 * @returns indented string
 */
export function indent(string: string, indent: string = '  ') {
  return string.split('\n')
      .map((line) => `${indent}${line}`)
      .join('\n')
}
