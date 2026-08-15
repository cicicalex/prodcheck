/**
 * Renders the report with sample findings so the layout can be judged in a real
 * terminal instead of a mockup.
 *
 *   node demo.mjs                 coloured, as a user sees it
 *   NO_COLOR=1 node demo.mjs      accessibility / CI-log path
 *   node demo.mjs | cat           piped — colour must switch itself off
 *   node demo.mjs --clean         the zero-findings state
 */

import { renderReport, exitCode } from './src/ui/report.mjs';
import { renderHelp } from './src/ui/help.mjs';
import { renderJson } from './src/ui/json.mjs';

const findings = [
  {
    severity: 'critical',
    rule: 'webhook-swallows-2xx',
    file: 'src/api/stripe/route.ts',
    line: 42,
    impact:
      'The catch block returns 200 without re-throwing. Stripe marks the event delivered and never retries, so a failed payment is lost with no trace in your logs.',
    fix: {
      remove: ['} catch (e) { return new Response(null, { status: 200 }) }'],
      add: ['} catch (e) { logger.error(e); throw e }'],
    },
  },
  {
    severity: 'high',
    rule: 'rate-limit-bypass',
    file: 'src/middleware.ts',
    line: 18,
    impact:
      'X-Forwarded-For is used as the rate-limit identity. Any client can set the header and issue unlimited requests. Resolve the address through the framework instead of parsing the header — configuring proxy trust does not make a hand-rolled read safe, it just means the validated address was available and went unused.',
    fix: {
      remove: ['const ip = req.headers.get("x-forwarded-for")'],
      add: [
        "app.set('trust proxy', <hops you control>)  // once, at app setup",
        'const ip = req.ip  // the address the framework resolved, not the raw header',
      ],
    },
  },
  {
    severity: 'medium',
    rule: 'account-delete-blocked',
    file: 'prisma/schema.prisma',
    line: 96,
    impact:
      'Four foreign keys reference User with NO ACTION, so a delete always fails. GDPR Article 17 requires erasure to be possible.',
  },
];

const argv = process.argv.slice(2);
const clean = argv.includes('--clean');
const result = {
  findings: clean ? [] : findings,
  filesScanned: 340,
  durationMs: 1200,
  lockedChecks: 5,
};

if (argv.includes('--help') || argv.includes('-h')) {
  process.stdout.write(renderHelp('0.1.0'));
} else if (argv.includes('--json')) {
  process.stdout.write(
    renderJson(result, { version: '0.1.0', root: '.', startedAt: '2026-08-14T20:00:00.000Z' })
  );
  process.exitCode = exitCode(result.findings);
} else {
  process.stdout.write(renderReport(result));
  process.exitCode = exitCode(result.findings);
}
