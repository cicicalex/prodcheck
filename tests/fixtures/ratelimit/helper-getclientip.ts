/**
 * The shape production code actually has, and the one this rule was blind to:
 * the forgeable value is resolved inside a helper and handed back to a caller
 * that keys a hand-rolled limiter with it.
 *
 * Neither half looks wrong on its own. getClientIp never mentions a limiter,
 * checkRateLimit never mentions a header, and the bug lives only in the seam
 * between them — which is exactly the seam a per-function reachability search
 * cannot see unless it follows the return value out.
 *
 * Both gates are also spelled the way TypeScript spells them: the body brace of
 * an annotated function is preceded by its RETURN TYPE, not by the `)` of its
 * parameter list, and reading those as plain blocks widened "the enclosing
 * function" to the whole file for every .ts route in the tree.
 */
const buckets = new Map<string, { count: number; resetAt: number }>();

function getClientIp(headersList: Headers): string {
  const forwarded = headersList.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return 'unknown';
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = buckets.get(ip);
  if (!entry || entry.resetAt < now) {
    buckets.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  entry.count += 1;
  return entry.count <= 10;
}

export async function POST(request: Request) {
  const clientIp = getClientIp(request.headers);
  if (!checkRateLimit(clientIp)) {
    return Response.json({ error: 'Too many requests' }, { status: 429 });
  }
  return Response.json({ ok: true });
}
