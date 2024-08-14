/**
 * This function returns true if the given object has entries
 * @param obj - object to check
 * @return true if the given object has entries
 */
export function hasEntries<T extends object>(obj: T): boolean {
  return Object.entries(obj).length > 0;
}

/**
 * This function will return a result with promise result or error
 * @param promise - promise
 * @return result
 */
export function safePromise<T>(promise: Promise<T>): Promise<
    { success: true, data: T, error?: never } |
    { success: false, error: unknown, data?: never }
> {
  return promise
      .then((data) => ({success: true, data} satisfies { success: true, data: T }))
      .catch((error) => ({success: false, error}));
}

/**
 * This function will throw the given error
 * @param error - error to throw
 * @return never
 */
export function _throw(error: unknown): never {
  throw error;
}

/**
 * This function maps the given value with the given function
 * @param value - value to map
 * @param fn - mapping function
 * @return mapped value
 */
export function mapValue<T, R>(value: T, fn: (value: T) => R): R {
  return fn(value);
}

/**
 * This function will ensure that the given object is not empty, otherwise it will throw an error
 * @param obj - object to check
 * @return the given object
 */
export function ensureHasEntries<T extends object>(obj: T): T {
  if (!hasEntries(obj)) throw Error('Illegal argument, object can not be empty');
  return obj;
}

/**
 * This function will return a new array with unique values
 * @param iterable - an iterable
 * @return array with unique values
 */
export function unique<T>(iterable: Iterable<T>): T[] {
  return Array.from(new Set(iterable));
}

/**
 * This function will transform an array to an array of tuples
 * @param iterable - an iterable
 * @return array of tuples
 */
export function tuplesOf<T>(iterable: Iterable<T>): [T, T | undefined][] {
  const result: [T, T | undefined][] = [];
  const iterator = iterable[Symbol.iterator]();
  let iteratorResult;
  while (!(iteratorResult = iterator.next()).done) {
    result.push([
      iteratorResult.value,
      iterator.next().value,
    ]);
  }
  return result;
}

/**
 * This function will create a regular expression from a wildcard pattern
 * @param pattern - wildcard pattern
 * @param flags - regular expression flags
 * @return regular expression
 */
export function regexpOfWildcardPattern(pattern: string, flags?: string): RegExp {
  const regexp = escapeRegexp(pattern)
      .replace(/\\\*/g, '.+') // replace * with match one or more characters
      .replace(/\\\?/g, '.'); // replace ? with match one characters
  return RegExp(`^${regexp}$`, flags);
}

/**
 * Escape regular expression special characters
 * @param string - string to escape
 * @return escaped string
 */
export function escapeRegexp(string: string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * This function will return a new object created from mapped entries of the given object
 * @param object - an object
 * @param fn - mapping function
 * @return new mapped object
 */
export function mapObjectEntries<V, U>(
    object: Record<string, V>,
    fn: (entry: [string, V]) => [string, U],
): Record<string, U> {
  return Object.fromEntries(Object.entries(object).map(fn)) as Record<string, U>;
}

/**
 * This function will return a new object from filtered entries of the given object
 * @param object - an object
 * @param fn - filter function
 * @return new filtered object
 */
export function filterObjectEntries<V>(
    object: Record<string, V>,
    fn: (entry: [string, V]) => boolean,
): Record<string, V> {
  return Object.fromEntries(Object.entries(object).filter(fn));
}

/**
 * This function will return a promise that will resolve after the given time
 * @param ms - time in milliseconds
 * @return promise
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * This function will return a promise that will resolve after the given time
 * @param fn - function to retry
 * @param options - retry options
 * @param options.retries - number of retries
 * @param options.delay - delay between retries
 * @param options.onRetry - function to call on retry, return false to stop retrying
 * @param options.onError - function to call on error, return false to stop retrying
 * @return promise
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
  const {retries, delay} = options;
  for (let attempts = 0; attempts < retries; attempts++) {
    try {
      const result = await fn();
      if (!options.onRetry || !options.onRetry(result)) {
        return result;
      }
    } catch (error: unknown) {
      if (options.onError && !options.onError(error)) {
        throw error;
      }
      if (attempts >= retries) {
        throw error;
      }
      await sleep(delay);
    }
  }
  throw Error('Illegal state');
}

/**
 * Indent string
 * @param string - string to indent
 * @param indent - indent string
 * @param subsequentIndent - subsequent indent string
 * @return indented string
 */
export function indent(string: string, indent = '  ', subsequentIndent = ' '.repeat(indent.length)): string {
  return string.split('\n')
      .map((line, index) => `${index === 0 ? indent : subsequentIndent}${line}`)
      .join('\n');
}

/**
 * Check if the given value is a record
 * @param value - a value
 * @return true if the given object is a record
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Joins multiple regular expressions into a single regular expression
 * @param regexps - regular expressions
 * @param flags - regular expression flags
 * @return regular expression
 */
export function joinRegExp(regexps: (string | RegExp)[], flags?: string): RegExp {
  return new RegExp(regexps
      .map((r) => typeof r === 'string' ? r : r.source)
      .join(''), flags);
}

/**
 * Convert string to base64
 * @param value - string to convert
 * @return base64 string
 */
export function toBase64(value?: string | null) {
  return Buffer.from(value ?? '').toString('base64');
}

export type Optional<T, K extends keyof T> = Pick<Partial<T>, K> & Omit<T, K>;
