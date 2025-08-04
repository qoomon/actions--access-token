import {z} from 'zod';
import YAML from 'yaml';

export const hasEntries: z.core.$ZodCheck<object> = z.superRefine((obj, ctx) => {
  if (Object.keys(obj).length === 0) {
    ctx.issues.push({
      code: 'custom',
      message: `Invalid ${Array.isArray(obj) ? 'array' : 'object'}: must have at least one entry`,
      input: obj,
    });
  }
});

/**
 * This function will format a zod issue
 * @param issue - zod issue
 * @return formatted issue
 */
export function formatZodIssue(issue: z.core.$ZodIssue): string {
  let result = '- ';
  if (issue.path.length > 0) {
    result += `${issue.path.join('.')}: `;
  }

  if (issue.code === 'invalid_union') {
    result += `Union errors:\n` + issue.errors
        .map((error) => error
            .map((error) => formatZodIssue(error)
                .split('\n')
                .map((line) => '  ' + line)
                .join('\n')
            ).join('\n')
        ).join('\n');
  } else {
    result += issue.message;
  }

  return result;
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
