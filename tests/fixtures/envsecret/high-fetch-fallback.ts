// HIGH. The bug this rule was built from, reduced to its shape.
//
// zpl-finance/src/app/api/health-check/route.ts read the FMP key exactly like
// this. The key was deleted when the account was cancelled; 'demo' is Financial
// Modeling Prep's public sandbox key, so every request kept succeeding against
// a shared credential and the only symptom was the invoice.
const FMP_BASE = 'https://financialmodelingprep.com/api/v3';

export async function GET() {
  const apiKey = process.env.FMP_API_KEY ?? 'demo';

  const res = await fetch(`${FMP_BASE}/quote/AAPL?apikey=${apiKey}`);
  const quotes = await res.json();

  return Response.json({ ok: res.ok, quotes });
}
