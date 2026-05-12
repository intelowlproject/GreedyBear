import { defineConfig } from "eslint/config";
import globals from "globals";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default defineConfig([{
    extends: compat.extends("eslint:recommended"),

    languageOptions: {
        globals: {
            ...globals.browser,
            ...globals.node,
            process: "readonly",
            global: "readonly",
            vi: "readonly",
        },

        ecmaVersion: 12,
        sourceType: "module",

        parserOptions: {
            ecmaFeatures: {
                jsx: true,
            },
        },
    },

    rules: {
        "no-unused-vars": "off",
        "react/prop-types": "off",
        "react/display-name": "off",
        "react/react-in-jsx-scope": "off",
        "import/prefer-default-export": "off",
        "no-console": "off",
        "react/jsx-props-no-spreading": "off",
    },
}, {
    files: ["tests/**/*.{js,jsx}"],

    languageOptions: {
        globals: {
            describe: "readonly",
            it: "readonly",
            expect: "readonly",
            beforeEach: "readonly",
            afterEach: "readonly",
            test: "readonly",
            afterAll: "readonly",
            beforeAll: "readonly",
            vi: "readonly",
        },
    },
}]);