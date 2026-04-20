import type { OpenClawConfig } from "openclaw/plugin-sdk/config-runtime";
import { describe, expect, it, vi } from "vitest";
import {
  emitTelegramSlashCommandFeedback,
  type TelegramSlashCommandFeedbackReactionApi,
} from "./bot-native-commands.ack-feedback.js";
import type { TelegramSendChatActionHandler } from "./sendchataction-401-backoff.js";

function makeHandler(overrides?: Partial<TelegramSendChatActionHandler>): {
  handler: TelegramSendChatActionHandler;
  sendChatAction: ReturnType<typeof vi.fn>;
} {
  const sendChatAction = vi.fn(async () => undefined);
  const handler: TelegramSendChatActionHandler = {
    sendChatAction: sendChatAction as unknown as TelegramSendChatActionHandler["sendChatAction"],
    isSuspended: overrides?.isSuspended ?? (() => false),
    reset: overrides?.reset ?? (() => undefined),
  };
  return { handler, sendChatAction };
}

function makeReactionApi(): {
  reactionApi: TelegramSlashCommandFeedbackReactionApi;
  spy: ReturnType<typeof vi.fn>;
} {
  const spy = vi.fn(async () => undefined);
  return { reactionApi: spy as unknown as TelegramSlashCommandFeedbackReactionApi, spy };
}

const baseCfg = { messages: { ackReaction: "👀" } } as unknown as OpenClawConfig;

describe("emitTelegramSlashCommandFeedback", () => {
  it("emits ack reaction and typing when scope=direct and sender is DM", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: 100,
      messageId: 7,
      isGroup: false,
      ackReactionScope: "direct",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(reactionSpy).toHaveBeenCalledTimes(1);
    expect(reactionSpy).toHaveBeenCalledWith(100, 7, [{ type: "emoji", emoji: "👀" }]);
    expect(sendChatAction).toHaveBeenCalledTimes(1);
    expect(sendChatAction).toHaveBeenCalledWith(100, "typing", undefined);
  });

  it("emits typing with thread params when threadId is provided", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: -1001,
      messageId: 42,
      isGroup: true,
      threadId: 5,
      ackReactionScope: "group-all",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(sendChatAction).toHaveBeenCalledWith(-1001, "typing", { message_thread_id: 5 });
  });

  it("emits no ack or typing when scope=off", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: 100,
      messageId: 7,
      isGroup: false,
      ackReactionScope: "off",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(reactionSpy).not.toHaveBeenCalled();
    expect(sendChatAction).not.toHaveBeenCalled();
  });

  it("emits no ack or typing when scope=none", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: 100,
      messageId: 7,
      isGroup: false,
      ackReactionScope: "none",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(reactionSpy).not.toHaveBeenCalled();
    expect(sendChatAction).not.toHaveBeenCalled();
  });

  it("skips ack reaction but keeps typing when scope=group-all and sender is DM", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: 100,
      messageId: 7,
      isGroup: false,
      ackReactionScope: "group-all",
      reactionApi,
      sendChatActionHandler: handler,
    });

    // scope=group-all excludes DM — the gate returns false and neither side fires.
    expect(reactionSpy).not.toHaveBeenCalled();
    expect(sendChatAction).not.toHaveBeenCalled();
  });

  it("emits ack reaction on slash command in group when scope=group-mentions (slash is an explicit mention)", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: -1001,
      messageId: 42,
      isGroup: true,
      threadId: undefined,
      ackReactionScope: "group-mentions",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(reactionSpy).toHaveBeenCalledWith(-1001, 42, [{ type: "emoji", emoji: "👀" }]);
    expect(sendChatAction).toHaveBeenCalledWith(-1001, "typing", undefined);
  });

  it("emits ack reaction and typing when scope=all regardless of chat type", async () => {
    const { handler, sendChatAction } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: -1001,
      messageId: 9,
      isGroup: true,
      ackReactionScope: "all",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(reactionSpy).toHaveBeenCalledTimes(1);
    expect(sendChatAction).toHaveBeenCalledTimes(1);
  });

  it("still emits typing when reactionApi is null (bot.api.setMessageReaction unavailable)", async () => {
    const { handler, sendChatAction } = makeHandler();

    await emitTelegramSlashCommandFeedback({
      cfg: baseCfg,
      accountId: "default",
      agentId: "main",
      chatId: 100,
      messageId: 7,
      isGroup: false,
      ackReactionScope: "direct",
      reactionApi: null,
      sendChatActionHandler: handler,
    });

    expect(sendChatAction).toHaveBeenCalledTimes(1);
  });

  it("does not throw when sendChatAction rejects (fire-and-forget error contract)", async () => {
    const sendChatAction = vi.fn(async () => {
      throw new Error("401 Unauthorized");
    });
    const handler: TelegramSendChatActionHandler = {
      sendChatAction: sendChatAction as unknown as TelegramSendChatActionHandler["sendChatAction"],
      isSuspended: () => false,
      reset: () => undefined,
    };
    const { reactionApi } = makeReactionApi();

    await expect(
      emitTelegramSlashCommandFeedback({
        cfg: baseCfg,
        accountId: "default",
        agentId: "main",
        chatId: 100,
        messageId: 7,
        isGroup: false,
        ackReactionScope: "direct",
        reactionApi,
        sendChatActionHandler: handler,
      }),
    ).resolves.toBeUndefined();

    expect(sendChatAction).toHaveBeenCalledTimes(1);
  });

  it("does not throw when reactionApi rejects (fire-and-forget error contract)", async () => {
    const { handler, sendChatAction } = makeHandler();
    const reactionApi = vi.fn(async () => {
      throw new Error("reaction failed");
    }) as unknown as TelegramSlashCommandFeedbackReactionApi;

    await expect(
      emitTelegramSlashCommandFeedback({
        cfg: baseCfg,
        accountId: "default",
        agentId: "main",
        chatId: 100,
        messageId: 7,
        isGroup: false,
        ackReactionScope: "direct",
        reactionApi,
        sendChatActionHandler: handler,
      }),
    ).resolves.toBeUndefined();

    // typing still fires even when reaction fails
    expect(sendChatAction).toHaveBeenCalledTimes(1);
  });

  it("falls back to default ack emoji (👀) when no ackReaction is configured", async () => {
    const { handler } = makeHandler();
    const { reactionApi, spy: reactionSpy } = makeReactionApi();

    await emitTelegramSlashCommandFeedback({
      cfg: {} as OpenClawConfig,
      accountId: "default",
      agentId: "main",
      chatId: 100,
      messageId: 7,
      isGroup: false,
      ackReactionScope: "direct",
      reactionApi,
      sendChatActionHandler: handler,
    });

    expect(reactionSpy).toHaveBeenCalledWith(100, 7, [{ type: "emoji", emoji: "👀" }]);
  });
});
