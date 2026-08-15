import { Webhook } from 'svix';

export async function handleHook(req) {
  const wh = new Webhook(process.env.SVIX_SECRET);
  try {
    const msg = wh.verify(await req.text(), Object.fromEntries(req.headers));
    await deliver(msg);
    return new Response(null, { status: 204 });
  } catch (err) {
    logger.error(err);
    throw err;
  }
}

async function deliver(msg) {}
