// CLEAN, and it is the patch this rule prints, written out in full.
//
// The variable is read ONCE, at module load, and a missing value stops the
// process before it can serve a request. There is no fallback to judge, so
// there is nothing here to report — and the failure mode is the good one: the
// deploy fails in the first second with the name of the variable in the error,
// instead of succeeding for three weeks against somebody else's account.
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error('API_KEY is not set');

const API_BASE = process.env.API_BASE_URL || 'https://api.example.com';

export async function quote(symbol) {
  const res = await fetch(`${API_BASE}/quote/${symbol}`, {
    headers: { authorization: `Bearer ${API_KEY}` },
  });
  if (!res.ok) throw new Error(`quote failed: ${res.status}`);
  return res.json();
}
