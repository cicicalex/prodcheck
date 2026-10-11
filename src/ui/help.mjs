/**
 * The help screen.
 *
 * This is the most-read screen the tool has and the one most often treated as
 * an afterthought. Two rules drive the layout:
 *
 *   1. It must fit one terminal height (~24 rows) with no scrolling. A help
 *      screen you have to scroll is a help screen nobody reads to the end.
 *   2. Examples come before the options list. Almost everyone arrives wanting
 *      one working invocation, not a taxonomy of flags. The first example is
 *      the one 90% of users need.
 */

import { style } from './theme.mjs';

const NAME = 'prodcheck';

export function renderHelp(version = '0.0.0') {
  const h = (s) => style.dim(s.toUpperCase());
  const flag = (s) => style.bold(s);

  return `
${style.bold(NAME)} ${style.dim(`v${version}`)} — finds the production bugs that ship green

${h('usage')}
  ${NAME} [path] [options]       ${style.dim(`built artifacts: ${NAME} artifacts --help`)}

${h('examples')}
  ${style.cyan(`${NAME} .`)}                     scan the current directory
  ${style.cyan(`${NAME} src/ --fail-on high`)}   fail the build at HIGH or above
  ${style.cyan(`${NAME} . --json`)}              machine-readable, for CI

${h('options')}
  ${flag('--fail-on <level>')}   exit 1 at this severity or above ${style.dim('[default: high]')}
                      ${style.dim('critical | high | medium | low | never')}
  ${flag('--json')}              emit JSON instead of the report
  ${flag('--no-color')}          disable colour ${style.dim('(or set NO_COLOR=1)')}
  ${flag('-v, --version')}       print version and exit
  ${flag('-h, --help')}          this screen

${h('exit codes')}
  ${style.green('0')} clean    ${style.yellow('1')} findings at or above --fail-on    ${style.red('2')} scan failed

${style.dim(`  ${NAME} runs offline. No account, no telemetry, no network calls.`)}
${style.dim('  A Zero Point Logic tool — zeropointlogic.io')}
`;
}
