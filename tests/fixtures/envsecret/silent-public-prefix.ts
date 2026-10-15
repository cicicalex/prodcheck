/**
 * Prefixele publice: declarate de build tool, deci nu pot fi secrete.
 *
 * Modelat după `sentry.client.config.ts` din a-real-app, care a fost primul
 * fals pozitiv al regulii. Toate patru trebuie să rămână TĂCUTE.
 */

declare const Sentry: { init: (o: unknown) => void };
declare function fetch(u: string): Promise<unknown>;

// Next.js — inlined în bundle-ul de browser la build. Un DSN Sentry e endpoint
// de ingestie write-only, iar literalul e chiar al proiectului.
Sentry.init({
  dsn:
    process.env.NEXT_PUBLIC_SENTRY_DSN ??
    'https://0a3f51742b2ab999838446e964b59522@o4511169041727488.ingest.de.sentry.io/4511169231585360',
});

// Vite — acelaşi contract, alt build tool. Cu apel de reţea, ca să se vadă că
// nici promovarea la HIGH nu se declanşează.
export async function ping() {
  const token = process.env.VITE_ANALYTICS_TOKEN ?? 'pk_public_demo';
  return fetch(`https://plausible.io/api/event?token=${token}`);
}

// Create React App.
export const craKey = process.env.REACT_APP_MAPS_API_KEY ?? 'AIzaSyPublicDemoKey';

// SvelteKit / Astro.
export const skKey = process.env.PUBLIC_TURNSTILE_KEY ?? '1x00000000000000000000AA';
