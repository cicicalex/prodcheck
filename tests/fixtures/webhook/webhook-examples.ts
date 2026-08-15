/**
 * Fixture-ul de acceptare pentru SS001.
 *
 * Cinci cazuri BAD, patru GOOD. Detectorul trebuie să raporteze **exact 5**, și
 * niciunul dintre cele GOOD. Fișierul conține `constructEvent` și
 * `stripe-signature`, deci toate findingurile ies HIGH.
 *
 * Cazurile GOOD contează mai mult decât cele BAD. Un scaner care raportează
 * `res.status(500)` ca bug e dezinstalat după a doua rulare, iar atunci nu mai
 * prinde nici bug-urile reale.
 */

// Stub-uri ca fișierul să fie de sine stătător. Nu se execută niciodată.
declare const stripe: any;
declare const proceseaza: (e: any) => Promise<void>;
declare const inregistreaza: (e: any) => Promise<void>;
declare const log: (e: unknown) => void;
declare const NextResponse: any;

function eveniment(req: any) {
  return stripe.webhooks.constructEvent(
    req.body,
    req.headers["stripe-signature"],
    process.env.STRIPE_WEBHOOK_SECRET,
  );
}

// ─────────────────────────────────────────────────────────────────────
// BAD — toate trebuie raportate
// ─────────────────────────────────────────────────────────────────────

/** 200 explicit. Stripe marchează evenimentul livrat și nu mai reîncearcă. */
export async function bad1_status200Explicit(req: any, res: any) {
  try {
    await proceseaza(eveniment(req));
    res.status(200).json({ received: true });
  } catch (err) {
    log(err);
    res.status(200).json({ received: true });
  }
}

/** Fără status — `res.json()` trimite 200 implicit. Același efect, mai greu de văzut. */
export async function bad2_jsonImplicit(req: any, res: any) {
  try {
    await proceseaza(eveniment(req));
    res.json({ ok: true });
  } catch (err) {
    log(err);
    res.json({ ok: true });
  }
}

/** Next.js App Router. `NextResponse.json` fără status înseamnă tot 200. */
export async function bad3_nextResponse(req: any) {
  try {
    await proceseaza(eveniment(req));
    return NextResponse.json({ received: true });
  } catch (err) {
    log(err);
    return NextResponse.json({ received: true });
  }
}

/** `new Response` fără status — implicit 200. */
export async function bad4_newResponse(req: any) {
  try {
    await proceseaza(eveniment(req));
    return new Response("ok", { status: 200 });
  } catch (err) {
    log(err);
    return new Response("ok", { status: 200 });
  }
}

/** Fastify. 204 e tot 2xx — providerul îl citește ca livrat. */
export async function bad5_replyCode204(req: any, reply: any) {
  try {
    await proceseaza(eveniment(req));
    reply.code(200).send();
  } catch (err) {
    log(err);
    reply.code(204).send();
  }
}

// ─────────────────────────────────────────────────────────────────────
// GOOD — niciunul nu are voie să fie raportat
// ─────────────────────────────────────────────────────────────────────

/** 5xx pe eșec: providerul reîncearcă. Comportamentul corect. */
export async function good1_status500(req: any, res: any) {
  try {
    await proceseaza(eveniment(req));
    res.status(200).json({ received: true });
  } catch (err) {
    log(err);
    res.status(500).json({ error: "procesare eșuată" });
  }
}

/**
 * Răspunde, apoi re-aruncă pentru middleware-ul de erori.
 *
 * Cazul care testează garda #2: există un răspuns 2xx în catch, dar `throw`
 * înseamnă că eroarea NU e înghițită.
 */
export async function good2_reAruncare(req: any, res: any) {
  try {
    await proceseaza(eveniment(req));
    res.json({ ok: true });
  } catch (err) {
    res.json({ ok: true });
    throw err;
  }
}

/** 400 pe semnătură invalidă. Corect: n-are rost să reîncerce, e cerere falsă. */
export async function good3_semnaturaInvalida(req: any, res: any) {
  try {
    await proceseaza(eveniment(req));
    res.status(200).send();
  } catch (err) {
    log(err);
    res.status(400).send("semnătură invalidă");
  }
}

/**
 * Catch care DISCRIMINEAZĂ între tipuri de erori.
 *
 * 200 doar pentru cazul recunoscut ca „deja procesat" — corect, providerul nu
 * trebuie să reîncerce un duplicat. Pentru orice altă eroare nu returnează
 * nimic: loghează și cade prin la procesarea reală.
 *
 * **Modelat după cod real de producție.** A fost primul fals pozitiv al
 * detectorului, găsit rulându-l pe `zpl-finance-repo`.
 */
export async function good5_idempotentaConditionala(req: any, res: any) {
  const ev = eveniment(req);
  try {
    await inregistreaza(ev);
  } catch (err) {
    if ((err as any).code === "P2002") {
      return NextResponse.json({ received: true, duplicate: true });
    }
    // Orice altceva: fail-open, ca o problemă tranzitorie de bază de date să nu
    // piardă un eveniment legitim.
    log(err);
  }
  await proceseaza(ev);
  return NextResponse.json({ received: true });
}

/** Lanț cu status non-2xx. Verificarea trebuie să meargă înapoi pe lanț. */
export async function good4_lant503(req: any, res: any) {
  try {
    await proceseaza(eveniment(req));
    res.status(200).json({ received: true });
  } catch (err) {
    log(err);
    res.status(503).json({ retry: true });
  }
}
