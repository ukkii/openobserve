import { describe, expect, it, vi } from "vitest";

import useEnterpriseRoutes from "./useEnterpriseRoutes";

vi.mock("@/utils/zincutils", async (importOriginal) => ({
  ...(await importOriginal()),
  routeGuard: vi.fn((_to, _from, next) => next()),
}));

describe("community routes", () => {
  it("keeps community IAM routes and removes custom RBAC surfaces", () => {
    const routes = useEnterpriseRoutes();
    const iam = routes.find((route: any) => route.name === "iam");
    const names = iam.children.map((route: any) => route.name);

    expect(names).toEqual(
      expect.arrayContaining([
        "users",
        "ingestionTokens",
        "syntheticsTokens",
        "serviceAccounts",
        "organizations",
        "mcpServer",
      ]),
    );
    expect(names).not.toEqual(
      expect.arrayContaining(["groups", "editGroup", "roles", "editRole", "quota"]),
    );
  });

  it("keeps public synthetics routes available", () => {
    const names = useEnterpriseRoutes().map((route: any) => route.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "synthetics",
        "synthetics-add",
        "synthetics-edit",
        "synthetic-monitor-results",
        "synthetics-run-detail",
      ]),
    );
  });
});
