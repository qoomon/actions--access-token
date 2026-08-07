import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import jest from 'eslint-plugin-jest';

export default [
  eslint.configs.recommended,
  ...tseslint.configs.strict, // includes tseslint.configs.recommended
  ...tseslint.configs.stylistic,
  {
    rules: {
      'max-len': ['error', {'code': 120, 'ignoreComments': true}],
      'no-trailing-spaces': ['error', {'skipBlankLines': true}],
      '@typescript-eslint/consistent-type-definitions': 'off',
      '@typescript-eslint/no-unused-vars': ['error', {
        varsIgnorePattern: '^_',
        argsIgnorePattern: '^_',
      }],
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
