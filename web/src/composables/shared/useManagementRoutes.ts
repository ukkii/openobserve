import { routeGuard } from "@/utils/zincutils";
import { slackRouteGuard } from "./slackRouteGuard";

const Settings = () => import("@/components/settings/index.vue");

const useManagementRoutes = () => [
  {
    path: "settings",
    name: "settings",
    component: Settings,
    meta: {
      keepAlive: true,
      titleKey: "menu.settings",
    },
    redirect: (to: any) => ({ name: "general", query: to.query }),
    beforeEnter(to: any, from: any, next: any) {
      routeGuard(to, from, next);
    },
    children: [
      {
        path: "general",
        name: "general",
        meta: {
          titleKey: "settings.groupGeneral",
          allowOnEmptyData: true,
        },
        component: () => import("@/components/settings/General.vue"),
        beforeEnter(to: any, from: any, next: any) {
          routeGuard(to, from, next);
        },
      },
      {
        path: "organization",
        name: "organizationSettings",
        meta: {
          titleKey: "settings.orgLabel",
        },
        component: () => import("@/components/settings/OrganizationSettings.vue"),
        beforeEnter(to: any, from: any, next: any) {
          routeGuard(to, from, next);
        },
      },
      {
        path: "alert_destinations",
        redirect: (to: any) => ({ name: "alertDestinations", query: to.query }),
      },
      {
        path: "templates",
        redirect: (to: any) => ({ name: "alertTemplates", query: to.query }),
      },
      {
        path: "alert_sources",
        redirect: (to: any) => ({ name: "alertSources", query: to.query }),
      },
      {
        path: "synthetics_locations",
        name: "syntheticsLocations",
        component: () => import("@/components/settings/SyntheticsLocationsList.vue"),
        meta: {
          keepAlive: true,
          titleKey: "routeTitles.syntheticsLocations",
          allowOnEmptyData: true,
        },
        beforeEnter(to: any, from: any, next: any) {
          routeGuard(to, from, next);
        },
      },
      {
        path: "slack",
        name: "slack",
        component: () => import("@/components/settings/Slack.vue"),
        meta: {
          titleKey: "routeTitles.slackApp",
        },
        beforeEnter: slackRouteGuard,
      },
    ],
  },
];

export default useManagementRoutes;
