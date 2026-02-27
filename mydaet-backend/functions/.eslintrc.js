module.exports = {
  root: true,
  env: {
    es2021: true,
    node: true,
  },
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: "module",
  },
  plugins: [
    "@typescript-eslint",
    "import",
  ],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:import/errors",
    "plugin:import/warnings",
    "plugin:import/typescript",
  ],
  ignorePatterns: [
    "lib/**/*",
    "node_modules/**/*",
  ],
  rules: {
    /* ---- Practical rules ---- */
    "quotes": ["error", "double"],
    "semi": ["error", "always"],

    /* ---- Disable rules that block Firebase TS ---- */
    "require-jsdoc": "off",
    "valid-jsdoc": "off",
    "max-len": "off",
    "indent": "off",

    /* ---- TypeScript specific ---- */
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/explicit-module-boundary-types": "off",

    /* ---- Import rules ---- */
    "import/no-unresolved": "off",
  },
  overrides: [
    {
      files: ["scripts/**/*.js", "tests/**/*.js"],
      rules: {
        "@typescript-eslint/no-var-requires": "off",
      },
    },
  ],
};
