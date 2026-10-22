import { defineConfig } from 'tsdown';
import { isBuiltin } from 'node:module'

export default defineConfig({
  target: 'node24',
  minify:true,
  treeshake:true,
  shims: true, // Polyfills __dirname and __filename for ESM
  banner: {
    // Shims CommonJS 'require' for ESM
    js: "import { createRequire } from 'module';" +
        "const require = createRequire(import.meta.url);",
  },
  deps: {
    // Bundle all dependencies
    alwaysBundle: (id) => !isBuiltin(id),
    onlyBundle: false, 
  },
});
