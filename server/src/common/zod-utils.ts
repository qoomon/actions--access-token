import {z} from 'zod';
import YAML from 'yaml';
import {$ZodIssue} from 'zod/v4/core';

/**
 * This function will format a zod issue
 * @param issue - zod issue
 * @return formatted issue
 */
export function formatZodIssue(issue: $ZodIssue): string {
  if (issue.path.length === 0) return issue.message;
  return `${issue.path.join('.')}: ${issue.message}`;
}

export const JsonTransformer = z.string().transform((val, ctx) => {
  try {
    return JSON.parse(val);
  } catch (error: unknown) {
    ctx.issues.push({
      code: 'custom',
      message: (error as { message?: string }).message,
      input: val,
    });
    return z.NEVER;
  }
});

export const YamlTransformer = z.string().transform((str, ctx) => {
  try {
    return YAML.parse(str);
  } catch (error: unknown) {
    ctx.addIssue({code: 'custom', message: (error as { message?: string }).message});
    return z.NEVER;
  }
});
