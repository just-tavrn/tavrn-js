// SPDX-License-Identifier: Apache-2.0
/**
 * The claims of an app token (APPLICATIONS.md §2.1), read without verification: the node verifies every request,
 * the bot only needs to know its device (`dev`), application (`app`), home node (`iss`) and expiry (`exp`).
 */
import { b64urlDecode } from "@tavrn/sdk";
import { BotError } from "./errors";

export interface AppTokenClaims {
  /** The bot's home node domain. */
  iss: string;
  /** The bot's user ULID. */
  sub: string;
  /** The bot device bound to the token (§3.2). */
  dev: string;
  /** The application ULID. */
  app: string;
  /** Expiry, seconds since the epoch. */
  exp: number;
  /** The owner's address. */
  owner?: string;
  /** The token's scopes. */
  scp?: string[];
}

/** Parses an app token's payload; {@link BotError} `token_invalid` for anything that is not one. */
export function appTokenClaims(token: string): AppTokenClaims {
  const parts = token.trim().split(".");
  if (parts.length !== 3) throw new BotError("token_invalid", "The token is not a JWT; use the secret shown when the token was created");
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]!))) as Record<string, unknown>;
  } catch {
    throw new BotError("token_invalid", "The token's payload cannot be read");
  }
  const str = (k: string) => (typeof payload[k] === "string" && payload[k] ? (payload[k] as string) : null);
  if (payload.typ !== "app") throw new BotError("token_invalid", "This is not an app token (typ must be \"app\"); create a token in the application settings");
  const iss = str("iss");
  const sub = str("sub");
  const dev = str("dev");
  const app = str("app");
  const exp = typeof payload.exp === "number" ? payload.exp : null;
  if (!iss || !sub || !dev || !app || exp === null) throw new BotError("token_invalid", "The app token lacks iss, sub, dev, app or exp");
  const scp = Array.isArray(payload.scp) ? payload.scp.filter((s): s is string => typeof s === "string") : undefined;
  return { iss, sub, dev, app, exp, owner: str("owner") ?? undefined, scp };
}
