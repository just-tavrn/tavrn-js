// SPDX-License-Identifier: Apache-2.0
/**
 * @tavrn/bot – the bot runtime for Node.js (protocol/APPLICATIONS.md §3, §5, §11 step 5): `createBot()` with the bot
 * key file, the token's bot device, end-to-end encryption as an MLS member, messages, commands and remote
 * installations over federated sessions. See README.md.
 */
export { BOT_VERSION, Bot, DEFAULT_STATE_DIR, JOINABLE_KINDS, createBot, threadTitle, type BotAttachment, type BotEvents, type BotInfo, type BotMessage, type BotOptions, type BotThread, type CreateThreadOptions, type DmRequestEvent, type InstallEvent, type MemberEvent, type MessageDeleteEvent, type PollOptions, type PollResults, type PollVoteEvent, type ReactionEvent, type ReportEvent, type RoomRef, type SendOptions, type ThreadEvent, type TokenExpiringEvent, type UndecryptableEvent, type UninstallEvent } from "./bot";
export { ComponentInteraction, ComponentRouter, button, modal, row, select, textInput, withComponents, type ComponentEventData, type ComponentHandler, type Matcher } from "./components";
// The shapes and checks of components (APPLICATIONS.md §5.10) are the SDK's; the encrypted values' checks are @tavrn/e2ee's.
export { validateComponents, validateComponentValues, validateModal, validateModalValues, type Button, type Component, type Modal, type ModalInput, type Row, type Select, type SelectOption } from "@tavrn/sdk";
export { COMPONENT_VALUES_TYPE, ComponentValuesVerifier, MODAL_VALUES_TYPE, type ValuesRejection } from "@tavrn/e2ee";
export { CommandRouter, Interaction, type CommandCrypto, type CommandHandler, type CommandInvokeData, type InteractionResult, type InvokeContext, type ReplyContent, type ReplyOptions } from "./commands";
// The argument checks of encrypted invocations (§5.8) are the shared ones of @tavrn/e2ee.
export { COMMAND_ARGS_TYPE, CommandArgsVerifier, type ArgsCheck, type ArgsRejection } from "@tavrn/e2ee";
export { BotError, type BotErrorCode } from "./errors";
export { retiredLeaf, sealUnderPolicy, type GhostPolicy } from "./ghosts";
export type { CommandDefinition, CommandSet } from "@tavrn/sdk";
export { createKeyFile, defaultKeyFile, parseKey, readKey } from "./keyfile";
export { consoleLogger, silentLogger, type BotLogger, type LogFields } from "./logger";
export { appTokenClaims, type AppTokenClaims } from "./token";
export { MessageTracker, validReaction, type MessageChanges, type ReactionChange } from "./reactions";
export { retryAfterMs, retryingFetch, type RetryOptions } from "./ratelimit";
export { MAX_ATTACHMENTS, uploadCategory, type BotFile, type DownloadedFile, type UploadCategory } from "./uploads";
export {
  ACTIVITY_TYPES,
  MAX_PRESENCE_TEXT,
  MAX_REASON_CHARS,
  MAX_TEXT_CHARS,
  MAX_TIMEOUT_MINUTES,
  MAX_VOICE_STATUS,
  PRESENCE_STATUSES,
  REPORT_STATUSES,
  activityRequest,
  checkContent,
  presenceRequest,
  type ActivityInput,
  type ActivityType,
  type PresenceInput,
  type PresenceStatus,
  type ReportStatus,
} from "./validate";
// Embeds (APPLICATIONS.md §6.4) are checked with the shared rules of @tavrn/e2ee.
export { EmbedsInvalidError, MAX_EMBEDS, embedsProblem, type EmbedField, type MessageEmbed } from "@tavrn/e2ee";
// Hook requests (interactions URL, event subscriptions; APPLICATIONS.md §6.3) are verified with the SDK's verifier.
export { HookVerifier, verifyHookRequest, type HookEvent, type HookFailure, type HookRequest, type HookVerification, type HookVerifierOptions } from "@tavrn/sdk";
