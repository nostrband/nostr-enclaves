import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import terser from "@rollup/plugin-terser";
import typescript from "@rollup/plugin-typescript";

export default {
  input: "src/index.ts",
  output: [
    {
      file: "dist/index.js",
      format: "esm",
      sourcemap: true
    },
    {
      file: "dist/index.cjs",
      format: "cjs",
      sourcemap: true
    }
  ],
  plugins: [
    resolve({
      browser: true,            // for browser + Node support
      preferBuiltins: false     // don't prioritize Node built-ins
    }),
    commonjs({
      transformMixedEsModules: true,  // Handle mixed ES/CJS modules
      requireReturnsDefault: 'auto'    // Handle default exports correctly
    }),
    typescript({
      tsconfig: "tsconfig.json",
      declaration: true,
      declarationDir: "dist/types",
      rootDir: "src",
      exclude: ["**/*.test.ts", "**/__tests__/**"]
    }),
    terser()
  ],
  external: []
};
