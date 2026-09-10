import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    // Bounded thread workers avoid Windows child-process startup contention.
    pool: 'threads',
    maxWorkers: 2,
  },
})
