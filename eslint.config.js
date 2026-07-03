'use strict';

const js = require('@eslint/js');
const globals = require('globals');
const prettierConfig = require('eslint-config-prettier');
const pluginMocha = require('eslint-plugin-mocha').default;

module.exports = [
  {
    ignores: ['node_modules/**', 'dist/**'],
  },
  js.configs.recommended,
  prettierConfig,
  pluginMocha.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'error',
      'no-empty': 'error',
      eqeqeq: ['error', 'always'],
      'no-unused-vars': 'warn',
      'no-unsafe-negation': 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      'mocha/no-mocha-arrows': 'off',
      'mocha/no-setup-in-describe': 'off',
    },
  },
];
