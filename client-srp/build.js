const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['dist/index.js'],
  bundle: true,
  outfile: 'dist/nopasswords-srp.js',
  format: 'iife',
  globalName: 'NoPasswordsSRP',
  sourcemap: true,
  minify: true,
}).catch(() => process.exit(1));
