import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    redis: 'src/redis/index.ts',
    otel: 'src/otel/index.ts',
    metrics: 'src/metrics/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: { resolve: true },
  sourcemap: true,
  clean: true,
  target: 'node20',
  platform: 'node',
  splitting: false,
  treeshake: true,
});
