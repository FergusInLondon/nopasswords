const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['dist/index.js'],
  bundle: true,
  outfile: 'dist/nopasswords.js',
  format: 'iife',
  globalName: 'NoPasswords',
  minify: true,
  sourcemap: true,
}).catch(() => process.exit(1));
