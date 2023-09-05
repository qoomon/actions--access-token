import type {JestConfigWithTsJest} from 'ts-jest'

export default <JestConfigWithTsJest>{
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  testPathIgnorePatterns: [
    '<rootDir>/dist/',
    '<rootDir>/node_modules/',
    '<rootDir>/deployments/.+/infrastructure/',
  ],
  moduleNameMapper: {
    '^(\\.\\.?/.*)\\.js$': '$1',
  },
}
