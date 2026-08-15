// The clean file. Nothing here is a webhook and nothing here keys a limiter,
// so both rules read it and both stay quiet.
import { Redis } from '@upstash/redis';

export const redis = Redis.fromEnv();

export async function getUser(id: string) {
  return redis.hgetall(`user:${id}`);
}
