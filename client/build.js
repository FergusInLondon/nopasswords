const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['dist/index.js'],
  bundle: true,
  outfile: 'dist/nopasswords-webauthn.js',
  format: 'iife',
  globalName: 'NoPasswordsWebAuthn',
  minify: true,
  sourcemap: true,
}).catch(() => process.exit(1));
