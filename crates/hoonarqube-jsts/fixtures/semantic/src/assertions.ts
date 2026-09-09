export function redundant(value: string): string {
  return value as string;
}

export function narrowing(value: string | null): string {
  if (value === null) return "fallback";
  return value as string;
}

export function generic<T>(value: T): T {
  return value;
}

export function genericAssertion(value: unknown): string {
  return generic(value) as string;
}
