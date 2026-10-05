const { defineConfig } = require('eslint/config');
const expo = require('eslint-config-expo/flat');
module.exports = defineConfig([
  expo,
  { ignores: ['ios/**', 'android/**', 'artifacts/**', 'native-build/**', 'modules/syn-native/ios/Frameworks/**'] },
  { files: ['tests/*.test.tsx'], languageOptions: { globals: { jest: 'readonly', test: 'readonly', expect: 'readonly', beforeEach: 'readonly' } } },
]);
