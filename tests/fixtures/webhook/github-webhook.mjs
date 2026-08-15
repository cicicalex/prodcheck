export async function handleWebhook(req) {
  try {
    const event = JSON.parse(await req.text());
    await dispatch(event);
    return new Response(null, { status: 204 });
  } catch (err) {
    console.error(err);
    return new Response(null);
  }
}

async function dispatch(event) {}
