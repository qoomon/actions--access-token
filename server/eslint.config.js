import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import jest from 'eslint-plugin-jest';
import {FlatCompat} from '@eslint/eslintrc';

const compat = new FlatCompat({
  baseDirectory: import.meta.dirname,
});

export default [
  eslint.configs.recommended,
  ...tseslint.configs.strict, // includes tseslint.configs.recommended
  ...tseslint.configs.stylistic,
  ...compat.extends('plugin:require-extensions/recommended'),
  {
    rules: {
      'max-len': ['error', {'code': 120, 'ignoreComments': true}],
      'no-trailing-spaces': ['error', {'skipBlankLines': true}],
      '@typescript-eslint/consistent-type-definitions': 'off',
    },
  },
  {
    files: ['test/**'],
    ...jest.configs['flat/recommended'],
  },
  {
    ignores: [
      '**/dist/**',
      'deployments/**/infrastructure/**',
    ],
  },
];
