import type {JestConfigWithTsJest} from 'ts-jest';

export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  moduleNameMapper: {
    '^(\\.\\.?/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        ignoreDeprecations: '6.0',
      },
    }],
  },
} as JestConfigWithTsJest;
