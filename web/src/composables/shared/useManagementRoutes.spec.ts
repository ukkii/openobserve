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

import enLocale from "@/locales/languages/en-US.json";
import { routeGuard } from "@/utils/zincutils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { slackRouteGuard } from "./slackRouteGuard";
import useManagementRoutes from "./useManagementRoutes";

vi.mock("@/utils/zincutils", () => ({
  routeGuard: vi.fn(),
}));

vi.mock("./slackRouteGuard", () => ({
  slackRouteGuard: vi.fn(),
}));

const childRoutes = () => useManagementRoutes()[0].children;

const collectTitleKeys = (routes: any[]): string[] =>
  routes.flatMap((route) => [
    ...(route?.meta?.titleKey ? [route.meta.titleKey] : []),
    ...collectTitleKeys(route?.children ?? []),
  ]);

const enMessage = (key: string) =>
  key.split(".").reduce<any>((node, part) => node?.[part], enLocale);

describe("useManagementRoutes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("registers only the community settings surface", () => {
    const routes = useManagementRoutes();
    const names = routes.flatMap((route) => [
      route.name,
      ...(route.children ?? []).map((child) => child.name).filter(Boolean),
    ]);

    expect(names).toEqual([
      "settings",
      "general",
      "organizationSettings",
      "syntheticsLocations",
      "slack",
    ]);
    expect(routes).toHaveLength(1);
  });

  it("does not register premium management routes", () => {
    const premiumRoutes = new Set([
      "enterpriseFeatureLocked",
      "enterpriseFeatures",
      "modelPricing",
      "modelPricingEditor",
      "llmProviders",
      "genAiAgentMapping",
      "query_management",
      "cipherKeys",
      "aiToolsets",
      "pipelineDestinations",
      "telephonySettings",
      "storageSettings",
      "nodes",
      "domainManagement",
      "regexPatterns",
      "passwordPolicy",
      "correlationSettings",
      "license",
      "announcementBanners",
      "announcementBannerEditor",
      "orgnizationManagement",
      "orgDomainMapping",
    ]);
    const names = useManagementRoutes().flatMap((route) => [
      route.name,
      ...(route.children ?? []).map((child) => child.name).filter(Boolean),
    ]);

    expect(names.filter((name) => premiumRoutes.has(name))).toEqual([]);
  });

  it("preserves organization queries through settings and legacy alert redirects", () => {
    const query = { org_identifier: "default", action: "import" };
    const settings = useManagementRoutes()[0];
    const destinations = childRoutes().find((route) => route.path === "alert_destinations");
    const templates = childRoutes().find((route) => route.path === "templates");
    const sources = childRoutes().find((route) => route.path === "alert_sources");

    expect(settings.redirect({ query })).toEqual({ name: "general", query });
    expect(destinations?.redirect?.({ query })).toEqual({ name: "alertDestinations", query });
    expect(templates?.redirect?.({ query })).toEqual({ name: "alertTemplates", query });
    expect(sources?.redirect?.({ query })).toEqual({ name: "alertSources", query });
  });

  it("keeps empty organizations able to configure general and synthetic locations", () => {
    const general = childRoutes().find((route) => route.name === "general");
    const locations = childRoutes().find((route) => route.name === "syntheticsLocations");

    expect(general?.meta?.allowOnEmptyData).toBe(true);
    expect(locations?.meta?.allowOnEmptyData).toBe(true);
  });

  it("guards community settings routes", () => {
    const to = { path: "/settings/general" };
    const from = { path: "/" };
    const next = vi.fn();
    const settings = useManagementRoutes()[0];
    const general = childRoutes().find((route) => route.name === "general");
    const slack = childRoutes().find((route) => route.name === "slack");

    settings.beforeEnter(to, from, next);
    general?.beforeEnter?.(to, from, next);
    slack?.beforeEnter?.(to, from, next);

    expect(routeGuard).toHaveBeenCalledTimes(2);
    expect(slackRouteGuard).toHaveBeenCalledWith(to, from, next);
  });

  it("uses valid English title keys", () => {
    const titleKeys = collectTitleKeys(useManagementRoutes());

    expect(titleKeys.length).toBeGreaterThan(0);
    for (const titleKey of titleKeys) {
      expect(enMessage(titleKey), `no en-US message for "${titleKey}"`).toBeTypeOf("string");
    }
  });
});
