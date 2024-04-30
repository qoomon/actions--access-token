import {z} from 'zod'

/**
 * This function will format a zod issue
 * @param issue - zod issue
 * @returns formatted issue
 */
export function formatZodIssue(issue: z.ZodIssue): string {
  if (issue.path.length === 0) return issue.message
  return issue.path.join('.') + ': ' + issue.message
}
