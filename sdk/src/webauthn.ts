// SPDX-License-Identifier: Apache-2.0
/**
 * WebAuthn JSON helpers (PROTOCOL.md §5a.4). The node serves options as the JSON form of
 * `PublicKeyCredentialCreationOptions` / `…RequestOptions` wrapped in `{ publicKey }` with binary values
 * in base64url and expects `PublicKeyCredential.toJSON()` back, without the PRF result.
 */

type Json = Record<string, unknown>;

/** RFC 4648 §5 base64url without padding. */
export function b64urlEncode(bytes: ArrayBuffer | ArrayBufferView): string {
  const u8 = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

interface JsonParsers {
  parseCreationOptionsFromJSON?: (o: Json) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (o: Json) => PublicKeyCredentialRequestOptions;
}

function native(): JsonParsers {
  return typeof PublicKeyCredential === "undefined" ? {} : (PublicKeyCredential as unknown as JsonParsers);
}

function publicKeyOf(options: Json): Json {
  const pk = options.publicKey;
  if (!pk || typeof pk !== "object" || typeof (pk as Json).challenge !== "string") throw new Error("WebAuthn options without publicKey.challenge");
  return pk as Json;
}

function convertDescriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((d: Json) => ({ ...(d as object), type: "public-key", id: b64urlDecode(String(d.id)) }) as PublicKeyCredentialDescriptor);
}

function convertExtensions(ext: unknown): AuthenticationExtensionsClientInputs | undefined {
  if (!ext || typeof ext !== "object") return undefined;
  const out: Json = { ...(ext as Json) };
  const prf = (ext as Json).prf as { eval?: { first?: string; second?: string } } | undefined;
  if (prf?.eval?.first) {
    out.prf = { eval: { first: b64urlDecode(prf.eval.first), ...(prf.eval.second ? { second: b64urlDecode(prf.eval.second) } : {}) } };
  }
  return out as AuthenticationExtensionsClientInputs;
}

/** Server `options` of `webauthn/register/start` → argument of `navigator.credentials.create`. */
export function parseCreationOptions(options: Json): CredentialCreationOptions {
  const pk = publicKeyOf(options);
  const parse = native().parseCreationOptionsFromJSON;
  if (parse) return { publicKey: parse(pk) };
  const user = pk.user as Json;
  return {
    publicKey: {
      ...(pk as object),
      challenge: b64urlDecode(String(pk.challenge)),
      user: { ...(user as object), id: b64urlDecode(String(user.id)) } as unknown as PublicKeyCredentialUserEntity,
      excludeCredentials: convertDescriptors(pk.excludeCredentials),
      extensions: convertExtensions(pk.extensions),
    } as unknown as PublicKeyCredentialCreationOptions,
  };
}

/** Server `options` of `webauthn/login/start` → argument of `navigator.credentials.get`. */
export function parseRequestOptions(options: Json): CredentialRequestOptions {
  const pk = publicKeyOf(options);
  const mediation = options.mediation as CredentialMediationRequirement | undefined;
  const parse = native().parseRequestOptionsFromJSON;
  const publicKey = parse
    ? parse(pk)
    : ({ ...(pk as object), challenge: b64urlDecode(String(pk.challenge)), allowCredentials: convertDescriptors(pk.allowCredentials), extensions: convertExtensions(pk.extensions) } as PublicKeyCredentialRequestOptions);
  return mediation ? { publicKey, mediation } : { publicKey };
}

function bufferToB64(v: unknown): unknown {
  if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return b64urlEncode(v as ArrayBuffer);
  if (v && typeof v === "object" && !Array.isArray(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, bufferToB64(x)]));
  return v;
}

/**
 * `PublicKeyCredential.toJSON()` for registrations and assertions (also where the browser lacks it).
 * Still contains the PRF result if any: always pass the result through {@link stripPrfResults}.
 */
export function credentialToJSON(cred: PublicKeyCredential): Json {
  const r = cred.response as AuthenticatorResponse & Partial<AuthenticatorAttestationResponse & AuthenticatorAssertionResponse>;
  const response: Json = { clientDataJSON: b64urlEncode(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = b64urlEncode(r.attestationObject);
    if (typeof r.getTransports === "function") response.transports = r.getTransports();
  } else {
    if (r.authenticatorData) response.authenticatorData = b64urlEncode(r.authenticatorData);
    if (r.signature) response.signature = b64urlEncode(r.signature);
    if (r.userHandle) response.userHandle = b64urlEncode(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    response,
    clientExtensionResults: bufferToB64(cred.getClientExtensionResults()) as Json,
  };
}

/** Copy of a credential JSON without `clientExtensionResults.prf.results` (the node rejects it, ENCRYPTION.md §2.4). */
export function stripPrfResults<T extends Json>(json: T): T {
  const copy = JSON.parse(JSON.stringify(json)) as Json;
  for (const key of ["clientExtensionResults", "extensions"]) {
    const prf = (copy[key] as Json | undefined)?.prf as Json | undefined;
    if (prf && "results" in prf) delete prf.results;
  }
  return copy as T;
}

/** The 32-byte PRF output (`prf.results.first`) of a ceremony, or null if the authenticator gave none. */
export function prfFirst(cred: PublicKeyCredential): Uint8Array | null {
  const prf = (cred.getClientExtensionResults() as { prf?: { results?: { first?: BufferSource } } }).prf;
  const first = prf?.results?.first;
  if (!first) return null;
  const u8 = first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
  return u8.slice();
}

/** `clientExtensionResults.prf.enabled` of a registration. */
export function prfEnabled(cred: PublicKeyCredential): boolean {
  return !!(cred.getClientExtensionResults() as { prf?: { enabled?: boolean } }).prf?.enabled;
}
