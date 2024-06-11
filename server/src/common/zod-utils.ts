import {z} from 'zod'
import YAML from 'yaml'

/**
 * This function will format a zod issue
 * @param issue - zod issue
 * @returns formatted issue
 */
export function formatZodIssue(issue: z.ZodIssue): string {
  if (issue.path.length === 0) return issue.message
  return issue.path.join('.') + ': ' + issue.message
}


export const JsonTransformer = z.string().transform((str, ctx) => {
  try {
    return JSON.parse(str)
  } catch (error: unknown) {
    ctx.addIssue({code: 'custom', message: (error as { message?: string }).message})
    return z.NEVER
  }
})

export const YamlTransformer = z.string().transform((str, ctx) => {
  try {
    return YAML.parse(str)
  } catch (error: unknown) {
    ctx.addIssue({code: 'custom', message: (error as { message?: string }).message})
    return z.NEVER
  }
})

/**
 * Shortcut for creating a zod string with regex validation
 * @param regex - regex
 * @returns zod string
 */
export function zStringRegex(regex: RegExp) {
  // Invalid enum value. Expected 'read' | 'write', received 'invalid',
  return z.string().regex(regex, `Invalid format. Expected format ${regex}`)
}

