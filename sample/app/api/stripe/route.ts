// A Stripe webhook handler with the single most expensive "ships green" bug:
// the catch answers 200, so Stripe marks the event delivered and never retries.
import { stripe } from '@/lib/stripe';
import { fulfillOrder } from '@/lib/orders';

export async function POST(req: Request) {
  const signature = req.headers.get('stripe-signature')!;
  const body = await req.text();

  try {
    const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!);
    if (event.type === 'checkout.session.completed') await fulfillOrder(event.data.object);
  } catch (err) {
    return new Response('ok', { status: 200 });
  }

  return new Response('ok', { status: 200 });
}
