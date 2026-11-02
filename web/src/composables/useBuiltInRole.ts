import { computed } from "vue";
import { useStore } from "vuex";

export function builtInRoleCanMutate(role: unknown): boolean {
  return String(role ?? "").toLowerCase() !== "viewer";
}

export function useBuiltInRole() {
  const store = useStore();
  const canMutate = computed(() => builtInRoleCanMutate(store.state.currentuser?.role));
  const isViewer = computed(() => !canMutate.value);
  return { canMutate, isViewer };
}
