import { oldValue as legacyValue } from "./deprecated.js";
export { oldValue as legacyValue, currentValue } from "./deprecated.js";
export type { ValueAlias } from "./types.d.ts";

export function useLegacy(): number {
  return legacyValue;
}
