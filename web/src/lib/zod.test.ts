import { describe, expect, it } from 'vitest';
import { z } from './zod';

describe('zod config', () => {
  it('runs in jitless mode for strict CSP environments', () => {
    expect(z.config().jitless).toBe(true);
  });
});
