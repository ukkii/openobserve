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

import { createRouter, createWebHistory } from "vue-router";
import { getDecodedUserInfo, getPath, mergeRoutes } from "@/utils/zincutils";
import { gt } from "@/types/i18n";
import { builtInRoleCanMutate } from "@/composables/useBuiltInRole";

import userRoutes from "@/composables/shared/router";
import useOSRoutes from "@/composables/router";

const VIEWER_MUTATION_ROUTES = new Set([
  "addPanel",
  "importDashboard",
  "createPipeline",
  "pipelineEditor",
  "importPipeline",
  "addAlert",
  "editAlert",
  "addAnomalyDetection",
  "editAnomalyDetection",
  "addSlo",
  "editSlo",
  "addDowntime",
  "editDowntime",
]);

export function builtInRoleMayNavigate(role: unknown, routeName: unknown): boolean {
  return builtInRoleCanMutate(role) || !VIEWER_MUTATION_ROUTES.has(String(routeName ?? ""));
}

export default function (store: any) {
  let { parentRoutes, homeChildRoutes } = userRoutes();

  const envRoutes: any = useOSRoutes();

  // parentRoutes = parentRoutes.concat(envRoutes.parentRoutes);
  // homeChildRoutes = homeChildRoutes.concat(envRoutes.homeChildRoutes);
  parentRoutes = mergeRoutes(parentRoutes, envRoutes.parentRoutes);
  homeChildRoutes = mergeRoutes(homeChildRoutes, envRoutes.homeChildRoutes);

  // Filter out catchall route from homeChildRoutes
  const catchAllRoute = homeChildRoutes.find((r: any) => r.path === "/:catchAll(.*)*");
  const nonCatchAllRoutes = homeChildRoutes.filter((r: any) => r.path !== "/:catchAll(.*)*");

  const routes = [
    ...parentRoutes,
    {
      path: "/",
      component: () => import("@/layouts/MainLayout.vue"),
      children: [...nonCatchAllRoutes],
    },
    // Add catchall at the end to match any unmatched routes
    ...(catchAllRoute ? [catchAllRoute] : []),
  ];

  interface RouterMap {
    history: any;
    routes: any;
  }
  const routerMap: RouterMap = {
    history: createWebHistory(getPath()),
    // history: createWebHistory(window.location.pathname),
    routes: routes,
  };

  const router = createRouter(routerMap);

  router.beforeEach((to: any, from: any, next: any) => {
    // Set page title with OpenObserve prefix.
    //
    // Routes carry an i18n KEY (`meta.titleKey`), not the text: the route tables
    // are module-scope, so translating where a route is declared would freeze the
    // tab title at whatever locale happened to be active at import time. Resolving
    // here — per navigation — keeps it in the current locale. `gt` (not `t`)
    // because a navigation guard runs outside any component setup. `title` is the
    // English literal fallback the routes not yet migrated to `titleKey` still carry.
    const routeTitle = to.meta?.titleKey ? gt(to.meta.titleKey) : to.meta?.title;
    if (routeTitle) {
      // The brand prefix is a product noun, never translated; the page name is.
      document.title = `OpenObserve - ${routeTitle}`;
    } else {
      document.title = "OpenObserve";
    }

    const isAuthenticated = store.state.loggedIn;

    // Public routes (unauthenticated viewer plane) opt out of the auth guard
    // entirely — never redirect an anonymous visitor to /login.
    if (to.meta && to.meta.public) {
      next();
      return;
    }

    const role = store.state.currentuser?.role ?? store.state.userInfo?.role;
    if (isAuthenticated && !builtInRoleMayNavigate(role, to.name)) {
      next({ name: "home" });
      return;
    }

    if (
      !isAuthenticated &&
      (to.meta?.public === true ||
        to.path === "/cb" ||
        to.path === "/web/cb" ||
        to.path === "/slack/oauth/callback" ||
        to.path === "/web/slack/oauth/callback")
    ) {
      next();
    } else if (!isAuthenticated) {
      const sessionUserInfo = getDecodedUserInfo();

      if (
        to.path !== "/login" &&
        to.path !== "/cb" &&
        to.path != "/web/cb" &&
        sessionUserInfo === null
      ) {
        if (to.path !== "/logout" && to.path !== "/cb" && to.path != "/web/cb") {
          // If query params contain short_url, store that URL; else store the
          // current URL. Needed for the short URL feature: after login the user
          // is redirected to the stored short URL.
          if (Object.hasOwn(to.query, "short_url")) {
            window.sessionStorage.setItem("redirectURI", to.query.short_url);
          } else {
            window.sessionStorage.setItem("redirectURI", window.location.href);
          }
        }
        next({ path: "/login" });
      } else {
        if (sessionUserInfo !== null) {
          const userInfo = JSON.parse(String(sessionUserInfo));
          store.dispatch("login", {
            loginState: true,
            userInfo: userInfo,
          });
        }
        next();
      }
    } else {
      getDecodedUserInfo();
      next();
    }
  });

  return router;
}
