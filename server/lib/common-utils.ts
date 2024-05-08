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
}

/**
 * Escape regular expression special characters
 * @param string - string to escape
 * @returns escaped string
 */
export function escapeRegexp(string: string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
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
 * This function will return a new object from filtered entries of the given object
 * @param object - an object
 * @param fn - filter function
 * @returns new filtered object
 */
export function filterObject<V>(
    object: Record<string, V>,
    fn: (entry: [string, V]) => boolean,
): Record<string, V> {
  return Object.fromEntries(Object.entries(object).filter(fn))
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
 * This function will return a promise that will resolve after the given time
 * @param fn - function to retry
 * @param options - retry options
 * @param options.retries - number of retries
 * @param options.delay - delay between retries
 * @param options.onRetry - function to call on retry, return false to stop retrying
 * @param options.onError - function to call on error, return false to stop retrying
 * @returns promise
 */
export async function retry<T>(
    fn: () => Promise<T>,
    options: {
      retries: number,
      delay: number,
      onRetry?: (result: T) => boolean | Promise<boolean>,
      onError?: (error: unknown) => boolean | Promise<boolean>,
    } = {
      retries: 1,
      delay: 1000,
    },
): Promise<T> {
  const {retries, delay} = options
  for (let attempts = 0; attempts < retries; attempts++) {
    try {
      const result = await fn()
      if (!options.onRetry || !options.onRetry(result)) {
        return result
      }
    } catch (error: unknown) {
      if (options.onError && !options.onError(error)) {
        throw error
      }
      if (attempts >= retries) {
        throw error
      }
      await sleep(delay)
    }
  }
  throw Error('Illegal state')
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


/**
 * Check if the given value is a record
 * @param value - a value
 * @returns true if the given object is a record
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * Joins multiple regular expressions into a single regular expression
 * @param regexps - regular expressions
 * @returns regular expression
 */
export function joinRegExp(...regexps: RegExp[]): RegExp {
  return new RegExp(regexps.map((r) => r.source).join(''), regexps[regexps.length-1]?.flags)
}
