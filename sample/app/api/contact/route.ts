// A contact form behind an Upstash rate limiter keyed on a header the client
// sets: rotate the value and the limit does not exist for you.
import { Ratelimit } from '@upstash/ratelimit';
import { redis } from '@/lib/db';

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for') ?? 'anonymous';
  const limiter = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, '60 s') });

  const { success } = await limiter.limit(ip);
  if (!success) return new Response('Too many requests', { status: 429 });

  return Response.json({ ok: true });
}
