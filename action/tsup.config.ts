import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    main: 'src/action-main.ts',
    post: 'src/action-post.ts',
  },
  format: ['esm'],
  outExtension() {
    return { js: '.mjs' };
  },
  target: 'node24',
  outDir: 'dist',
  noExternal: [/(.*)/], // Bundle all dependencies into dist/index.mjs
  // splitting: false,
  clean: true,
  // minify: true,
  treeshake: true,
  shims: true, // Polyfills __dirname and __filename for ESM
  banner: {
    // Shims CommonJS 'require' calls if imported third-party libs use it internally
    js: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);",
  },
});
