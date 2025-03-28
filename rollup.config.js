import terser from '@rollup/plugin-terser'
import typescript from '@rollup/plugin-typescript'

export default {
	input: 'src/index.ts',
	output: [
		{
			file: 'dist/index.cjs.js',
			format: 'cjs',
			sourcemap: true,
		},
		{
			file: 'dist/index.esm.js',
			format: 'esm',
			sourcemap: true,
		},
	],
	plugins: [
		typescript({
			tsconfig: 'tsconfig.json',
		}),
		terser(),
	],
	external: [],
}
