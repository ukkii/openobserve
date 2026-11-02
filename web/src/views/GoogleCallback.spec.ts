// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import { flushPromises, mount } from "@vue/test-utils";
import { createI18n } from "vue-i18n";
import { createMemoryHistory, createRouter } from "vue-router";
import { createStore } from "vuex";
import { beforeEach, describe, expect, it, vi } from "vitest";
import GoogleCallback from "./GoogleCallback.vue";
import authService from "@/services/auth";
import organizationsService from "@/services/organizations";
import { redirectUser } from "@/utils/common";
import { expireSession } from "@/utils/sessionServices";
import { useLocalCurrentUser, useLocalOrganization, useLocalUserInfo } from "@/utils/storage";

vi.mock("@/services/auth", () => ({
  default: { get_google_session: vi.fn(), logout: vi.fn() },
}));
vi.mock("@/services/organizations", () => ({
  default: { list: vi.fn() },
}));
vi.mock("@/utils/storage", () => ({
  useLocalCurrentUser: vi.fn(),
  useLocalOrganization: vi.fn(),
  useLocalUserInfo: vi.fn(),
}));
vi.mock("@/utils/sessionServices", () => ({ expireSession: vi.fn() }));
vi.mock("@/utils/common", () => ({ redirectUser: vi.fn() }));

function setup() {
  const store = createStore({
    state: {
      loggedIn: false,
      userInfo: {} as Record<string, unknown>,
      organizations: [] as unknown[],
      selectedOrganization: {} as Record<string, unknown>,
      currentuser: {} as Record<string, unknown>,
    },
    mutations: {
      login(state, payload: { loginState: boolean; userInfo: Record<string, unknown> }) {
        state.loggedIn = payload.loginState;
        state.userInfo = payload.userInfo;
      },
      setOrganizations(state, payload: unknown[]) {
        state.organizations = payload;
      },
      setSelectedOrganization(state, payload: Record<string, unknown>) {
        state.selectedOrganization = payload;
      },
      setCurrentUser(state, payload: Record<string, unknown>) {
        state.currentuser = payload;
      },
    },
    actions: {
      login: ({ commit }, payload) => commit("login", payload),
      setOrganizations: ({ commit }, payload) => commit("setOrganizations", payload),
      setSelectedOrganization: ({ commit }, payload) => commit("setSelectedOrganization", payload),
      setCurrentUser: ({ commit }, payload) => commit("setCurrentUser", payload),
    },
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/google/cb", component: GoogleCallback },
      { path: "/", component: { template: "<div />" } },
      { path: "/logs", component: { template: "<div />" } },
    ],
  });
  const i18n = createI18n({
    legacy: false,
    messages: { en: { login: { signingIn: "Signing in" } } },
  });
  return { store, router, i18n };
}

describe("GoogleCallback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.sessionStorage.clear();
    vi.mocked(authService.get_google_session).mockResolvedValue({
      data: { email: "viewer@example.com", first_name: "View", last_name: "Er" },
    });
    vi.mocked(authService.logout).mockResolvedValue({ data: {} });
    vi.mocked(organizationsService.list).mockResolvedValue({
      data: {
        data: [
          { id: 2, identifier: "acme", name: "Acme", type: "default" },
          { id: 3, identifier: "other", name: "Other" },
        ],
      },
    });
  });

  it("bootstraps the community session and selects an organization", async () => {
    const { store, router, i18n } = setup();
    window.sessionStorage.setItem("redirectURI", "/logs");
    await router.push("/google/cb");
    await router.isReady();
    mount(GoogleCallback, { global: { plugins: [store, router, i18n] } });

    await flushPromises();

    expect(authService.get_google_session).toHaveBeenCalledOnce();
    expect(organizationsService.list).toHaveBeenCalledWith(0, 100000, "id", false, "");
    expect(useLocalUserInfo).toHaveBeenCalledOnce();
    expect(useLocalCurrentUser).toHaveBeenCalledOnce();
    expect(useLocalOrganization).toHaveBeenCalledWith(
      expect.objectContaining({ identifier: "acme", user_email: "viewer@example.com" }),
    );
    expect(store.state.loggedIn).toBe(true);
    expect(store.state.selectedOrganization).toEqual(
      expect.objectContaining({ identifier: "acme" }),
    );
    expect(redirectUser).toHaveBeenCalledWith("/logs");
    expect(authService.logout).not.toHaveBeenCalled();
    expect(expireSession).not.toHaveBeenCalled();
  });

  it("revokes the server session before expiring a failed bootstrap", async () => {
    vi.mocked(organizationsService.list).mockRejectedValueOnce(new Error("unavailable"));
    const { store, router, i18n } = setup();
    await router.push("/google/cb");
    await router.isReady();
    mount(GoogleCallback, { global: { plugins: [store, router, i18n] } });

    await flushPromises();

    expect(authService.logout).toHaveBeenCalledOnce();
    expect(expireSession).toHaveBeenCalledWith(store, { toLogin: true });
    expect(vi.mocked(authService.logout).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(expireSession).mock.invocationCallOrder[0],
    );
  });
});
