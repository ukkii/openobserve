import { describe, expect, it } from "vitest";

import { builtInRoleCanMutate } from "./useBuiltInRole";

describe("builtInRoleCanMutate", () => {
  it("keeps Viewer read-only regardless of role casing", () => {
    expect(builtInRoleCanMutate("viewer")).toBe(false);
    expect(builtInRoleCanMutate("Viewer")).toBe(false);
  });

  it("keeps mutation controls for community administrators and editors", () => {
    expect(builtInRoleCanMutate("admin")).toBe(true);
    expect(builtInRoleCanMutate("editor")).toBe(true);
  });
});
