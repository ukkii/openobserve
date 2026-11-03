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

import { routeGuard } from "@/utils/zincutils";
import store from "@/stores";

const syntheticsRouteGuard = (to: any, from: any, next: any) => {
  if (store.state.zoConfig?.synthetics_enabled === false) {
    next("/");
    return;
  }
  routeGuard(to, from, next);
};

const IdentityAccessManagement = () => import("@/views/IdentityAccessManagement.vue");

const Organizations = () => import("@/components/iam/organizations/AppOrganizations.vue");

const ServiceAccountsList = () =>
  import("@/components/iam/serviceAccounts/ServiceAccountsList.vue");

const Users = () => import("@/views/User.vue");

const useEnterpriseRoutes = () => {
  const routes: any = [
    {
      path: "iam",
      name: "iam",
      component: IdentityAccessManagement,
      meta: { allowOnEmptyData: true },
      beforeEnter(to: any, from: any, next: any) {
        routeGuard(to, from, next);
      },
      children: [
        {
          path: "users",
          name: "users",
          meta: {
            titleKey: "iam.basicUsers",
          },
          component: Users,
          beforeEnter(to: any, from: any, next: any) {
            routeGuard(to, from, next);
          },
        },
        {
          path: "ingestionTokens",
          name: "ingestionTokens",
          meta: {
            titleKey: "iam.ingestionTokens",
          },
          component: () => import("@/components/iam/IngestionTokens.vue"),
          beforeEnter(to: any, from: any, next: any) {
            routeGuard(to, from, next);
          },
        },
        {
          path: "syntheticsTokens",
          name: "syntheticsTokens",
          meta: {
            titleKey: "iam.syntheticsTokens",
          },
          component: () => import("@/components/iam/SyntheticsTokens.vue"),
          beforeEnter(to: any, from: any, next: any) {
            syntheticsRouteGuard(to, from, next);
          },
        },
        {
          path: "serviceAccounts",
          name: "serviceAccounts",
          meta: {
            titleKey: "iam.serviceAccounts",
          },
          component: ServiceAccountsList,
          beforeEnter(to: any, from: any, next: any) {
            const store = (window as any).store;
            const serviceAccountEnabled = store?.state?.zoConfig?.service_account_enabled ?? true;

            if (!serviceAccountEnabled) {
              next({ name: "users", query: to.query });
              return;
            }

            routeGuard(to, from, next);
          },
        },
        {
          path: "organizations",
          name: "organizations",
          meta: {
            titleKey: "iam.organizations",
          },
          component: Organizations,
          beforeEnter(to: any, from: any, next: any) {
            routeGuard(to, from, next);
          },
        },
        {
          path: "mcpServer",
          name: "mcpServer",
          meta: { titleKey: "iam.mcpServerLabel" },
          component: () => import("@/components/iam/McpServer.vue"),
          beforeEnter(to: any, from: any, next: any) {
            routeGuard(to, from, next);
          },
        },
      ],
    },
  ];

  routes.push({
    path: "synthetics",
    name: "synthetics",
    component: () => import("@/views/SyntheticMonitoring.vue"),
    meta: { titleKey: "menu.synthetic", allowOnEmptyData: true },
    beforeEnter(to: any, from: any, next: any) {
      syntheticsRouteGuard(to, from, next);
    },
  });

  routes.push(
    {
      path: "synthetics/add",
      name: "synthetics-add",
      component: () => import("@/views/synthetics/CreateCheck.vue"),
      meta: { titleKey: "routeTitles.addCheck", allowOnEmptyData: true },
      beforeEnter(to: any, from: any, next: any) {
        syntheticsRouteGuard(to, from, next);
      },
    },
    {
      path: "synthetics/edit/:id",
      name: "synthetics-edit",
      component: () => import("@/views/synthetics/CreateCheck.vue"),
      meta: { titleKey: "synthetics.results.editCheck", allowOnEmptyData: true },
      beforeEnter(to: any, from: any, next: any) {
        syntheticsRouteGuard(to, from, next);
      },
    },
    {
      path: "synthetics/status-pages/edit/:id",
      name: "synthetics-status-page-edit",
      component: () => import("@/views/synthetics/status-pages/StatusPageEditor.vue"),
      meta: { titleKey: "statusPages.editTitle", allowOnEmptyData: true },
      beforeEnter(to: any, from: any, next: any) {
        syntheticsRouteGuard(to, from, next);
      },
    },
    {
      path: "synthetics/:id/results",
      name: "synthetic-monitor-results",
      component: () => import("@/views/synthetics/MonitorResults.vue"),
      meta: { titleKey: "synthetics.results.title", allowOnEmptyData: true },
      beforeEnter(to: any, from: any, next: any) {
        syntheticsRouteGuard(to, from, next);
      },
    },
    {
      path: "synthetics/:id/results/run/:runId/:executionId",
      name: "synthetics-run-detail",
      component: () => import("@/views/synthetics/RunDetail.vue"),
      meta: { titleKey: "synthetics.runDetail.title", allowOnEmptyData: true },
      beforeEnter(to: any, from: any, next: any) {
        syntheticsRouteGuard(to, from, next);
      },
    },
  );

  return routes;
};

export default useEnterpriseRoutes;
