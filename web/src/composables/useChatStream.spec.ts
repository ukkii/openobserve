// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { effectScope, nextTick, ref, type EffectScope } from "vue";

import type { ChatHistoryEntry, ChatMessage } from "@/ts/interfaces/chat";

const { mockFetchAiChat } = vi.hoisted(() => ({ mockFetchAiChat: vi.fn() }));

vi.mock("@/composables/useAiChat", () => ({
  default: () => ({ fetchAiChat: mockFetchAiChat }),
}));
vi.mock("@/utils/zincutils", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  getUUIDv7: vi.fn(() => "minted-session"),
}));
vi.mock("@/lib/feedback/Toast/useToast", () => ({ toast: vi.fn() }));

import {
  abortBackgroundStreams,
  sanitizePinnedContext,
  useChatStream,
} from "@/composables/useChatStream";

const scopes: EffectScope[] = [];

const makeStream = () => {
  const chatMessages = ref<ChatMessage[]>([]);
  const options = {
    chatMessages,
    currentChatId: ref<number | null>(null),
    currentTextSegment: ref(""),
    dbSaveToHistory: vi.fn(async () => 1),
    store: {
      state: { selectedOrganization: { identifier: "org" }, API_ENDPOINT: "" },
      dispatch: vi.fn(),
    } as any,
    router: { push: vi.fn() } as any,
    t: ((key: string) => key) as any,
    scrollToBottom: vi.fn(async () => {}),
    scrollToLoadingIndicator: vi.fn(async () => {}),
    autoNavigationPreferences: ref(new Map<number, boolean>()),
    pendingAutoNavigation: ref(true),
    isAutoNavigationEnabled: ref(true) as any,
    saveAutoNavigationPreferences: vi.fn(),
    startAnalyzingRotation: vi.fn(),
    stopAnalyzingRotation: vi.fn(),
    aiGeneratedTitle: ref<string | null>(null),
    animateTitle: vi.fn(),
    displayedStreamingContent: ref(""),
    typewriterAnimationId: ref<number | null>(null),
    resetTypewriterState: vi.fn(),
    animateStreamingText: vi.fn(),
  };
  const scope = effectScope();
  scopes.push(scope);
  const stream = scope.run(() => useChatStream(options))!;
  return { stream, options, chatMessages };
};

const sseResponse = (...events: object[]) => {
  const chunks = events.map((e) => new TextEncoder().encode(`data: ${JSON.stringify(e)}\n`));
  let i = 0;
  return {
    ok: true,
    body: {
      getReader: () => ({
        read: async () =>
          i < chunks.length
            ? { done: false, value: chunks[i++] }
            : { done: true, value: undefined },
      }),
    },
  };
};

const entry = (sessionId: string): ChatHistoryEntry => ({
  id: 7,
  timestamp: "",
  title: "t" as any,
  messages: [],
  sessionId,
});

describe("useChatStream", () => {
  beforeEach(() => {
    mockFetchAiChat.mockReset();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    scopes.splice(0).forEach((s) => s.stop());
    abortBackgroundStreams();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("re-attaches a stream detached by another instance to the very same array", () => {
    const home = makeStream();
    const sidebar = makeStream();
    const controller = new AbortController();
    const liveMsgs = home.chatMessages.value;
    home.stream.currentAbortController.value = controller;
    home.stream.currentSessionId.value = "s1";

    home.stream.detachCurrentStream();

    expect(home.stream.currentAbortController.value).toBeNull();
    expect(sidebar.stream.tryReattach(entry("s1"), 7)).toBe(true);
    expect(sidebar.chatMessages.value).toBe(liveMsgs);
    expect(sidebar.stream.currentAbortController.value).toBe(controller);
    expect(sidebar.stream.isLoading.value).toBe(true);
    expect(sidebar.stream.tryReattach(entry("s1"), 7)).toBe(false);
  });

  it("does not re-attach when no stream is registered for the session", () => {
    const { stream, chatMessages } = makeStream();
    const before = chatMessages.value;

    expect(stream.tryReattach(entry("unknown"), 7)).toBe(false);
    expect(chatMessages.value).toBe(before);
    expect(stream.isLoading.value).toBe(false);
  });

  it("abortBackgroundStreams aborts detached streams and forgets them", () => {
    const { stream } = makeStream();
    const controller = new AbortController();
    stream.currentAbortController.value = controller;
    stream.currentSessionId.value = "s2";
    stream.detachCurrentStream();

    abortBackgroundStreams();

    expect(controller.signal.aborted).toBe(true);
    expect(makeStream().stream.tryReattach(entry("s2"), 7)).toBe(false);
  });

  it("adds no chat message after a navigation to billing", async () => {
    vi.useFakeTimers();
    const { stream, options, chatMessages } = makeStream();

    await stream.handleNavigationAction({
      resource_type: "billing",
      action: "navigate_direct",
      label: "Plans",
      target: { path: "/billings/plans" },
    } as any);
    await vi.runAllTimersAsync();

    expect(options.router.push).toHaveBeenCalledWith(
      expect.objectContaining({ path: "/billings/plans" }),
    );
    expect(chatMessages.value).toHaveLength(0);
    expect(options.dbSaveToHistory).not.toHaveBeenCalled();
  });

  it("sets isLoading and mints the session id before its first await", async () => {
    mockFetchAiChat.mockResolvedValue({ cancelled: true });
    const { stream } = makeStream();

    const turn = stream.runTurn(false, []);

    expect(stream.isLoading.value).toBe(true);
    expect(stream.currentSessionId.value).toBe("minted-session");
    await turn;
  });

  it("runs teardown when the fetch throws, clearing loading and the controller", async () => {
    mockFetchAiChat.mockRejectedValue(new Error("network"));
    const { stream } = makeStream();

    await stream.runTurn(false, []);

    expect(stream.isLoading.value).toBe(false);
    expect(stream.currentAbortController.value).toBeNull();
  });

  it("disposeRenderFlush drops a pending trailing render", async () => {
    vi.useFakeTimers();
    const { stream, options, chatMessages } = makeStream();
    chatMessages.value = [
      { role: "assistant", content: "" as any, contentBlocks: [{ type: "text", text: "" }] },
    ];
    const block = () => chatMessages.value[0].contentBlocks![0];
    stream.isLoading.value = true;

    options.displayedStreamingContent.value = "a";
    await nextTick();
    expect(block().text).toBe("a");

    options.displayedStreamingContent.value = "ab";
    await nextTick();
    stream.disposeRenderFlush();
    vi.advanceTimersByTime(500);

    expect(block().text).toBe("a");
  });

  describe("pinned hand-off context", () => {
    const explicitContextOf = (call: number) => mockFetchAiChat.mock.calls[call][4];

    beforeEach(() => {
      // The pin is module-level; never let one case's pin leak into the next.
      makeStream().stream.clearPinnedContext();
    });

    it("sanitizePinnedContext drops every RCA scoping key and keeps the rest", () => {
      const clean = sanitizePinnedContext({
        currentPage: "incidents",
        org_id: "org",
        incident_id: "i1",
        incidentId: "i1",
        subject_id: "s1",
        subjectId: "s1",
        run_id: "r1",
        attempt_id: "a1",
        agent_type: "rca",
        rca_run: "x",
        rca_: "y",
        nested: { incident_id: "kept-inside" },
      });

      expect(clean).toEqual({
        currentPage: "incidents",
        org_id: "org",
        nested: { incident_id: "kept-inside" },
      });
    });

    it("sanitizePinnedContext does not mutate its input", () => {
      const input = { currentPage: "incidents", incident_id: "i1" };
      sanitizePinnedContext(input);
      expect(input).toEqual({ currentPage: "incidents", incident_id: "i1" });
    });

    it("sanitizePinnedContext returns null when nothing usable is left", () => {
      expect(sanitizePinnedContext({ incident_id: "i1", rca_run_id: "r" })).toBeNull();
      expect(sanitizePinnedContext({})).toBeNull();
      expect(sanitizePinnedContext(null)).toBeNull();
      expect(sanitizePinnedContext(undefined)).toBeNull();
      // An array is an object at runtime; the type rules it out, the guard must too.
      expect(sanitizePinnedContext(["a"] as unknown as Record<string, unknown>)).toBeNull();
    });

    it("sends the sanitized pin as explicitContext on every turn of the chat", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents", org_id: "org", incident_id: "i1" });
      await stream.runTurn(false, []);
      await stream.runTurn(false, []);

      expect(explicitContextOf(0)).toEqual({ currentPage: "incidents", org_id: "org" });
      expect(explicitContextOf(1)).toEqual({ currentPage: "incidents", org_id: "org" });
    });

    it("pins nothing when the context holds only RCA keys", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream } = makeStream();

      stream.setPinnedContext({ incident_id: "i1", subject_id: "s1" });
      await stream.runTurn(false, []);

      expect(explicitContextOf(0)).toBeUndefined();
    });

    it("sends the pin again on the session-restore retry", async () => {
      mockFetchAiChat
        .mockResolvedValueOnce(sseResponse({ type: "error", code: "session_owner_unavailable" }))
        .mockResolvedValueOnce(sseResponse({ content: "hi" }, { type: "complete" }));
      const { stream } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      await stream.runTurn(false, []);

      expect(mockFetchAiChat).toHaveBeenCalledTimes(2);
      expect(explicitContextOf(0)).toEqual({ currentPage: "incidents" });
      expect(explicitContextOf(1)).toEqual({ currentPage: "incidents" });
    });

    it("clearPinnedContext makes the next turn send no explicit context", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      stream.clearPinnedContext();
      await stream.runTurn(false, []);

      expect(explicitContextOf(0)).toBeUndefined();
    });

    it("a later setPinnedContext with only RCA keys removes the earlier pin", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      stream.setPinnedContext({ incident_id: "i1" });
      await stream.runTurn(false, []);

      expect(explicitContextOf(0)).toBeUndefined();
    });

    it("binds to the chat once saved: loading another chat drops it, reloading that chat keeps it", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream, options } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      options.currentChatId.value = 5;
      await nextTick();

      stream.releasePinnedContextFor(5);
      await stream.runTurn(false, []);
      expect(explicitContextOf(0)).toEqual({ currentPage: "incidents" });

      stream.releasePinnedContextFor(6);
      options.currentChatId.value = 6;
      await stream.runTurn(false, []);
      expect(explicitContextOf(1)).toBeUndefined();

      // Released for good: returning to chat 5 does not bring it back.
      options.currentChatId.value = 5;
      await stream.runTurn(false, []);
      expect(explicitContextOf(2)).toBeUndefined();
    });

    it("an unsaved pin is dropped by loading any existing chat", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      stream.releasePinnedContextFor(9);
      await stream.runTurn(false, []);

      expect(explicitContextOf(0)).toBeUndefined();
    });

    it("a pin bound to one chat is not sent on a turn of a different chat", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream, options } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      options.currentChatId.value = 5;
      await nextTick();
      options.currentChatId.value = 6;
      await nextTick();
      await stream.runTurn(false, []);

      expect(explicitContextOf(0)).toBeUndefined();
    });

    it("follows the chat across a remounted instance that reloads it", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const sidebar = makeStream();
      sidebar.stream.setPinnedContext({ currentPage: "incidents" });
      sidebar.options.currentChatId.value = 5;
      await nextTick();

      const overlay = makeStream();
      overlay.stream.releasePinnedContextFor(5);
      overlay.options.currentChatId.value = 5;
      await overlay.stream.runTurn(false, []);

      expect(explicitContextOf(0)).toEqual({ currentPage: "incidents" });
    });

    it("each turn gets its own copy of the pin", async () => {
      mockFetchAiChat.mockResolvedValue({ cancelled: true });
      const { stream } = makeStream();

      stream.setPinnedContext({ currentPage: "incidents" });
      await stream.runTurn(false, []);
      (explicitContextOf(0) as Record<string, unknown>).currentPage = "mutated";
      await stream.runTurn(false, []);

      expect(explicitContextOf(1)).toEqual({ currentPage: "incidents" });
    });
  });
});
