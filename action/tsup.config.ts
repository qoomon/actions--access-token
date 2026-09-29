import {defineConfig} from 'tsup';

export default defineConfig({
  clean: true,
  entry: {
    main: 'src/action-main.ts',
    post: 'src/action-post.ts',
  },
  target: 'node24',
  noExternal: [/(.*)/], // Bundle all dependencies
  minify:true,
  treeshake:true,
  format: ['esm'],
  outExtension() {
    return {js: '.mjs'};
  },
  shims: true, // Polyfills __dirname and __filename for ESM
  banner: {
    // Shims CommonJS 'require' for ESM
    js: "import { createRequire } from 'module';" +
        "const require = createRequire(import.meta.url);",
  },
});
