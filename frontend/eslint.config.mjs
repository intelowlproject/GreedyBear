import { defineConfig } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import importPlugin from "eslint-plugin-import";

export default defineConfig([
    js.configs.recommended,
    {

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

    plugins: {
        react,
        "react-hooks": reactHooks,
        import: importPlugin,
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