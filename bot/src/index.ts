// SPDX-License-Identifier: Apache-2.0
/**
 * @tavrn/bot – the bot runtime for Node.js (protocol/APPLICATIONS.md §3, §5, §11 step 5): `createBot()` with the bot
 * key file, the token's bot device, end-to-end encryption as an MLS member, messages, commands and remote
 * installations over federated sessions. See README.md.
 */
export { BOT_VERSION, Bot, DEFAULT_STATE_DIR, JOINABLE_KINDS, createBot, threadTitle, type BotEvents, type BotInfo, type BotMessage, type BotOptions, type InstallEvent, type SendOptions, type TokenExpiringEvent, type UndecryptableEvent, type UninstallEvent } from "./bot";
export { CommandRouter, Interaction, type CommandCrypto, type CommandHandler, type CommandInvokeData, type InteractionResult, type InvokeContext, type ReplyContent, type ReplyOptions } from "./commands";
// The argument checks of encrypted invocations (§5.8) are the shared ones of @tavrn/e2ee.
export { COMMAND_ARGS_TYPE, CommandArgsVerifier, type ArgsCheck, type ArgsRejection } from "@tavrn/e2ee";
export { BotError, type BotErrorCode } from "./errors";
export { retiredLeaf, sealUnderPolicy, type GhostPolicy } from "./ghosts";
export type { CommandDefinition, CommandSet } from "@tavrn/sdk";
export { createKeyFile, defaultKeyFile, parseKey, readKey } from "./keyfile";
export { consoleLogger, silentLogger, type BotLogger, type LogFields } from "./logger";
export { appTokenClaims, type AppTokenClaims } from "./token";
// Hook requests (interactions URL, event subscriptions; APPLICATIONS.md §6.3) are verified with the SDK's verifier.
export { HookVerifier, verifyHookRequest, type HookEvent, type HookFailure, type HookRequest, type HookVerification, type HookVerifierOptions } from "@tavrn/sdk";
