// SPDX-License-Identifier: Apache-2.0
/**
 * Structured logging of the bot runtime: a message and a flat object of fields. Pass your own logger (pino, winston,
 * …) to `createBot`; the default writes one JSON line per entry to stderr (`debug` only with `TAVRN_BOT_DEBUG=1`).
 * The runtime never logs secrets: no tokens, keys, ciphertexts or decrypted content.
 */
export type LogFields = Record<string, unknown>;

export interface BotLogger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

function line(level: string, message: string, fields?: LogFields): string {
  const extra: LogFields = {};
  for (const [k, v] of Object.entries(fields ?? {})) extra[k] = v instanceof Error ? { name: v.name, message: v.message, code: (v as { code?: unknown }).code } : v;
  return JSON.stringify({ time: new Date().toISOString(), level, msg: message, ...extra });
}

/** JSON lines on stderr. */
export function consoleLogger(opts: { debug?: boolean } = {}): BotLogger {
  const debug = opts.debug ?? (typeof process !== "undefined" && process.env.TAVRN_BOT_DEBUG === "1");
  return {
    debug: (m, f) => {
      if (debug) console.error(line("debug", m, f));
    },
    info: (m, f) => console.error(line("info", m, f)),
    warn: (m, f) => console.error(line("warn", m, f)),
    error: (m, f) => console.error(line("error", m, f)),
  };
}

/** Discards everything (tests). */
export const silentLogger: BotLogger = { debug: () => undefined, info: () => undefined, warn: () => undefined, error: () => undefined };
