import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it } from "vitest";

import IdentityAccessManagement from "@/views/IdentityAccessManagement.vue";
import i18n from "@/locales";
import store from "@/test/unit/helpers/store";
import router from "@/test/unit/helpers/router";

const stubs = {
  RouterView: { template: "<div>Router View</div>" },
  OPageLayout: { template: '<div data-test="iam-page"><slot name="sidebar" /><slot /></div>' },
  SectionRail: true,
};

describe("IdentityAccessManagement", () => {
  beforeEach(() => {
    store.state.zoConfig = { service_account_enabled: true };
    store.state.selectedOrganization = { identifier: "test-org" };
  });

  it("exposes only community IAM sections", async () => {
    const wrapper = mount(IdentityAccessManagement, {
      global: { provide: { store }, plugins: [i18n, router], stubs },
    });
    await flushPromises();
    const keys = wrapper.vm.sectionGroups.flatMap((group: any) =>
      group.items.map((item: any) => item.key),
    );

    expect(keys).toEqual(
      expect.arrayContaining([
        "users",
        "serviceAccounts",
        "ingestionTokens",
        "syntheticsTokens",
        "mcpServer",
        "organizations",
      ]),
    );
    expect(keys).not.toEqual(expect.arrayContaining(["groups", "roles", "quota"]));
    expect(wrapper.find('[data-test="iam-page"]').exists()).toBe(true);
    wrapper.unmount();
  });

  it("hides service accounts when the server disables them", async () => {
    store.state.zoConfig = { service_account_enabled: false };
    const wrapper = mount(IdentityAccessManagement, {
      global: { provide: { store }, plugins: [i18n, router], stubs },
    });
    await flushPromises();
    const serviceAccount = wrapper.vm.sectionGroups
      .flatMap((group: any) => group.items)
      .find((item: any) => item.key === "serviceAccounts");
    expect(serviceAccount.visible).toBe(false);
    wrapper.unmount();
  });
});
