<!-- Copyright 2026 OpenObserve Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<template>
  <div
    class="bg-card-glass-bg flex h-dvh w-full flex-col items-center justify-center gap-4"
    data-test="google-callback-loading"
  >
    <OSpinner size="lg" />
    <div class="text-text-secondary text-base">
      {{ t("login.signingIn") }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue";
import { useRouter } from "vue-router";
import { useStore } from "vuex";
import OSpinner from "@/lib/feedback/Spinner/OSpinner.vue";
import authService from "@/services/auth";
import organizationsService from "@/services/organizations";
import { useI18nTyped } from "@/types/i18n";
import { b64EncodeStandard } from "@/utils/formatters";
import { expireSession } from "@/utils/sessionServices";
import { isSameOriginRedirect } from "@/utils/safeUrl";
import { useLocalCurrentUser, useLocalOrganization, useLocalUserInfo } from "@/utils/storage";

interface Organization {
  id: string | number;
  identifier: string;
  name: string;
  type?: string;
}

interface OrganizationListResponse {
  data: {
    data: Organization[];
  };
}

const store = useStore();
const router = useRouter();
const { t } = useI18nTyped();

function selectOrganization(organizations: Organization[], email: string): void {
  store.dispatch("setOrganizations", organizations);
  const selected =
    organizations.find((organization) => organization.type === "default") ?? organizations[0];
  if (!selected) return;
  const option = {
    id: selected.id,
    identifier: selected.identifier,
    label: selected.name,
    user_email: email,
  };
  useLocalOrganization(option);
  store.dispatch("setSelectedOrganization", option);
}

async function finishLogin(): Promise<void> {
  try {
    const session = (await authService.get_google_session()).data;
    const userInfo = {
      email: session.email,
      name: [session.first_name, session.last_name].filter(Boolean).join(" ") || session.email,
      given_name: session.first_name,
      family_name: session.last_name,
    };
    const encoded = b64EncodeStandard(JSON.stringify(userInfo));
    if (encoded === undefined) throw new Error("Unable to encode the session identity");
    useLocalUserInfo(encoded);
    useLocalCurrentUser(JSON.stringify(userInfo));
    store.dispatch("setCurrentUser", userInfo);
    store.dispatch("login", { loginState: true, userInfo });

    const response = (await organizationsService.list(
      0,
      100000,
      "id",
      false,
      "",
    )) as OrganizationListResponse;
    selectOrganization(response.data.data, session.email);

    const redirectURI = window.sessionStorage.getItem("redirectURI");
    window.sessionStorage.removeItem("redirectURI");
    if (redirectURI && isSameOriginRedirect(redirectURI)) {
      if (redirectURI.startsWith("/")) await router.replace({ path: redirectURI });
      else window.location.href = redirectURI;
    } else {
      await router.replace({ path: "/" });
    }
  } catch {
    expireSession(store, { toLogin: true });
  }
}

onMounted(finishLogin);
</script>
