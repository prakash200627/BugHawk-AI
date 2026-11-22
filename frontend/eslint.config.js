import js from "@eslint/js";
import globals from "globals";

// TypeScript files are checked by `tsc` in `npm run build`.
// A TypeScript parser is not declared in package.json, so this config
// does not parse .ts or .tsx and does not add packages.
export default [
  {
    ignores: ["dist/**", "node_modules/**", "venv/**", "**/*.{ts,tsx}"],
  },
  js.configs.recommended,
  {
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
];
