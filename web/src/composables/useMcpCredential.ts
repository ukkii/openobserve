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

// Mints a dedicated MCP service account and, under RBAC, joins it to one shared read-only role per org.

import { ref, watch } from "vue";
import config from "@/aws-exports";
import http from "@/services/http";
import { useStore } from "vuex";
import { useI18nTyped } from "@/types/i18n";
import service_accounts from "@/services/service_accounts";
import { createRole, getAllRolePermissions, getResources, updateRole } from "@/services/iam";
import {
  buildReadonlyPermissions,
  type RolePermission,
} from "@/components/iam/roles/readonlyPreset";
import { queryClient } from "@/composables/query/queryClient";
import { serviceAccountKeys } from "@/services/service_accounts.querykeys";
import { iamKeys } from "@/services/iam.querykeys";
import { userKeys } from "@/services/users.querykeys";
import { buildServiceAccountEmail } from "@/components/iam/serviceAccounts/AddServiceAccount.schema";

// Underscore, not hyphen: create_role normalizes the name (non-[A-Za-z0-9_] → "_"), update_role does not.
export const MCP_READONLY_ROLE = "mcp_readonly";

// MCP is JSON-RPC over POST, which the route registry maps to PUT on `mcp` — a grant the read-only preset never makes.
const MCP_GRANTS = ["AllowList", "AllowPut"] as const;

/** `readonly`: joined to the shared role · `unscoped`: the role grants nothing or couldn't be applied · `rbacDisabled`: no RBAC to scope with. */
export type McpCredentialScope = "readonly" | "unscoped" | "rbacDisabled";

export interface McpCredential {
  scheme?: "Bearer";
  expiresAt?: number;
  /** Synthetic SA identifier — the Basic-auth username (`<name>.<org>@sa.internal`). */
  email: string;
  /** Show-once token — the Basic-auth password. Never persisted. */
  token: string;
  /** Null unless the account was actually added to the shared read-only role. */
  role: string | null;
  /** How far the token's access is limited; tells a null `role` from RBAC being off. */
  scope: McpCredentialScope;
}

// Show-once token: a remount must reuse it, and org-keyed because an org switch remounts the consumer.
const sessionCredentials = new Map<string, McpCredential>();

const grantKey = (perm: RolePermission): string => `${perm.object}|${perm.permission}`;

export function useMcpCredential() {
  const store = useStore();
  const { t } = useI18nTyped();

  const currentOrg = (): string => store.state.selectedOrganization?.identifier ?? "";
  const community = config.isEnterprise !== "true" && config.isCloud !== "true";
  const cacheKey = () => JSON.stringify([store.state.userInfo?.email ?? "", currentOrg()]);

  const generating = ref(false);
  const error = ref("");
  const credential = ref<McpCredential | null>(sessionCredentials.get(cacheKey()) ?? null);
  watch(cacheKey, (key) => {
    const cached = sessionCredentials.get(key);
    credential.value =
      cached && (!cached.expiresAt || cached.expiresAt > Date.now() * 1000) ? cached : null;
    error.value = "";
  });

  const revoke = async () => {
    if (!community) return;
    const key = cacheKey();
    const org = currentOrg();
    generating.value = true;
    error.value = "";
    try {
      await http().delete(`/api/${encodeURIComponent(org)}/mcp/credentials`);
      sessionCredentials.delete(key);
      if (key === cacheKey()) credential.value = null;
    } catch {
      error.value = t("ingestion.mcp.credential.revokeError");
    } finally {
      generating.value = false;
    }
  };

  // A 400 on a fixed, valid, non-standard role name can only mean it already exists.
  const ensureReadonlyRole = async (org: string): Promise<boolean> => {
    try {
      await createRole(MCP_READONLY_ROLE, org);
      return true;
    } catch (err: any) {
      if (err?.response?.status === 400) return false;
      throw err;
    }
  };

  // The shared role may predate a grant or be left empty by a failed first seed, so every mint tops it up.
  const missingRoleGrants = async (
    org: string,
    isMetaOrg: boolean,
    created: boolean,
  ): Promise<{ add: RolePermission[]; readable: boolean }> => {
    const res = await getResources(org);
    const readonly = buildReadonlyPermissions(res?.data ?? [], org, isMetaOrg);
    const mcpObject = `mcp:_all_${org}`;
    const desired = new Map(
      [...readonly, ...MCP_GRANTS.map((permission) => ({ object: mcpObject, permission }))].map(
        (perm) => [grantKey(perm), perm] as const,
      ),
    );

    // A role created a moment ago holds nothing, so its read is skipped.
    const held: RolePermission[] = created
      ? []
      : ((await getAllRolePermissions({ role_name: MCP_READONLY_ROLE, org_identifier: org }))
          ?.data ?? []);
    const heldKeys = new Set(held.map(grantKey));
    // OpenFGA rejects re-writing a tuple it already holds (update_role reports a 500), so only the gap is sent.
    const add = [...desired.values()].filter(
      (perm) => !heldKeys.has(grantKey(perm)) && !heldKeys.has(`${perm.object}|AllowAll`),
    );
    return { add, readable: readonly.length > 0 };
  };

  // Never throws: a role hiccup must not cost the caller the show-once token.
  const applyReadonlyRole = async (
    email: string,
    org: string,
  ): Promise<Pick<McpCredential, "role" | "scope">> => {
    if (!store.state.zoConfig?.rbac_enabled) return { role: null, scope: "rbacDisabled" };

    const isMetaOrg = org === store.state.zoConfig?.meta_org;
    try {
      const created = await ensureReadonlyRole(org);
      const { add, readable } = await missingRoleGrants(org, isMetaOrg, created);
      await updateRole({
        role_id: MCP_READONLY_ROLE,
        org_identifier: org,
        payload: { add, remove: [], add_users: [email], remove_users: [] },
      });
      return { role: MCP_READONLY_ROLE, scope: readable ? "readonly" : "unscoped" };
    } catch (roleErr) {
      console.error("MCP credential: read-only role could not be applied", roleErr);
      return { role: null, scope: "unscoped" };
    }
  };

  const generate = async (): Promise<McpCredential | null> => {
    const org = currentOrg();
    const key = cacheKey();
    const cached = sessionCredentials.get(cacheKey());
    if (cached && (!cached.expiresAt || cached.expiresAt > Date.now() * 1000)) {
      credential.value = cached;
      return credential.value;
    }

    generating.value = true;
    error.value = "";

    // Date.now() keeps two mints from colliding; base36 stays inside the slug charset.
    const name = `mcp-${Date.now().toString(36)}`;

    try {
      if (community) {
        const res = await http().post<{ email: string; token: string; expires_at: number }>(
          `/api/${encodeURIComponent(org)}/mcp/credentials`,
          {},
        );
        const issued: McpCredential = {
          email: res.data.email,
          token: res.data.token,
          scheme: "Bearer",
          expiresAt: res.data.expires_at,
          role: null,
          scope: "readonly",
        };
        sessionCredentials.set(key, issued);
        if (key === cacheKey()) credential.value = issued;
        return key === cacheKey() ? credential.value : issued;
      }
      const email = buildServiceAccountEmail(name, org);
      const res = await service_accounts.create({ email, first_name: "MCP client" }, org);
      const token = res?.data?.token;
      if (res?.data?.code !== 200 || !token) {
        throw new Error(res?.data?.message || t("ingestion.mcp.credential.error"));
      }
      // Raw service calls, so the IAM lists would otherwise keep serving their cached rows.
      void queryClient.invalidateQueries({ queryKey: serviceAccountKeys.all(org) });

      const issued: McpCredential = { email, token, ...(await applyReadonlyRole(email, org)) };
      if (key === cacheKey()) credential.value = issued;
      // The role may exist even when a later step failed, so drop these regardless.
      void queryClient.invalidateQueries({ queryKey: iamKeys.rolesAll(org) });
      void queryClient.invalidateQueries({ queryKey: userKeys.users(org) });
      sessionCredentials.set(key, issued);
      return key === cacheKey() ? credential.value : issued;
    } catch (err: any) {
      error.value =
        err?.response?.data?.message || err?.message || t("ingestion.mcp.credential.error");
      return null;
    } finally {
      generating.value = false;
    }
  };

  return { generate, revoke, generating, error, credential };
}
