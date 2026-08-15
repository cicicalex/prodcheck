/**
 * Global middleware: every /api route is rate limited before it runs.
 */
import { rateLimit } from './lib/rate-limit';

const limiter = rateLimit({
  windowMs: 60_000,
  max: 100,
  // One bucket per caller.
  keyGenerator: (req) => req.headers.get('x-forwarded-for') ?? '127.0.0.1',
});

export function middleware(req) {
  return limiter(req);
}

export const config = { matcher: '/api/:path*' };
