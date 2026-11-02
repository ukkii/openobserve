interface IdentityPayload {
  username: string;
  type: "linkedin" | "github" | "email" | "google" | "others" | "sso";
  firstname?: string;
  lastname?: string;
  company?: string;
}

export function useReo() {
  return {
    reoInit: async () => {},
    identify: async (_identity: IdentityPayload) => {},
    track: (_eventName: string, _payload?: Record<string, any>) => {},
    isLoaded: { value: false },
  };
}
