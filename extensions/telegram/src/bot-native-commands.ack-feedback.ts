import type { ReactionTypeEmoji } from "@grammyjs/types";
import {
  type AckReactionScope,
  resolveAckReaction,
  shouldAckReaction as shouldAckReactionGate,
} from "openclaw/plugin-sdk/channel-feedback";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-runtime";
import { logVerbose } from "openclaw/plugin-sdk/runtime-env";
import { withTelegramApiErrorLogging } from "./api-logging.js";
import { buildTypingThreadParams } from "./bot/helpers.js";
import type { TelegramSendChatActionHandler } from "./sendchataction-401-backoff.js";
import { isTelegramSupportedReactionEmoji } from "./status-reaction-variants.js";

export type TelegramSlashCommandFeedbackReactionApi = (
  chatId: number,
  messageId: number,
  reactions: Array<{ type: "emoji"; emoji: ReactionTypeEmoji["emoji"] }>,
) => Promise<unknown>;

export type EmitTelegramSlashCommandFeedbackParams = {
  cfg: OpenClawConfig;
  accountId: string;
  agentId: string;
  chatId: number;
  messageId: number;
  isGroup: boolean;
  threadId?: number;
  ackReactionScope: AckReactionScope;
  reactionApi: TelegramSlashCommandFeedbackReactionApi | null;
  sendChatActionHandler: TelegramSendChatActionHandler;
};

/**
 * Emit ack reaction + typing indicator for a Telegram slash command.
 *
 * A slash command is an explicit, user-initiated invocation — semantically
 * equivalent to "the bot was directly mentioned" — so we reuse the same
 * ack-reaction gate as regular messages but pin `effectiveWasMentioned` and
 * `shouldBypassMention` to true. Scope still controls DM-vs-group filtering.
 *
 * Fire-and-forget: failures are logged via the shared Telegram API error
 * pipeline and never abort the command execution itself.
 */
export async function emitTelegramSlashCommandFeedback(
  params: EmitTelegramSlashCommandFeedbackParams,
): Promise<void> {
  const {
    cfg,
    accountId,
    agentId,
    chatId,
    messageId,
    isGroup,
    threadId,
    ackReactionScope,
    reactionApi,
    sendChatActionHandler,
  } = params;

  const shouldAck = shouldAckReactionGate({
    scope: ackReactionScope,
    isDirect: !isGroup,
    isGroup,
    isMentionableGroup: isGroup,
    // Slash commands are always an explicit user opt-in; bypass mention gating.
    requireMention: true,
    canDetectMention: true,
    effectiveWasMentioned: true,
    shouldBypassMention: true,
  });
  if (!shouldAck) {
    return;
  }

  const ackReactionEmoji = resolveAckReaction(cfg, agentId, {
    channel: "telegram",
    accountId,
  });
  const typingThreadParams = buildTypingThreadParams(threadId);

  const tasks: Array<Promise<unknown>> = [];
  if (ackReactionEmoji && isTelegramSupportedReactionEmoji(ackReactionEmoji) && reactionApi) {
    tasks.push(
      withTelegramApiErrorLogging({
        operation: "setMessageReaction",
        fn: () => reactionApi(chatId, messageId, [{ type: "emoji", emoji: ackReactionEmoji }]),
      }).catch((err) => {
        logVerbose(`telegram slash react failed for chat ${chatId}: ${String(err)}`);
      }),
    );
  }
  tasks.push(
    withTelegramApiErrorLogging({
      operation: "sendChatAction",
      fn: () => sendChatActionHandler.sendChatAction(chatId, "typing", typingThreadParams),
    }).catch((err) => {
      logVerbose(`telegram slash typing failed for chat ${chatId}: ${String(err)}`);
    }),
  );

  // Fire-and-forget — we await here only so tests can observe the calls, but
  // failures on either side must never propagate out of this helper.
  await Promise.allSettled(tasks);
}
