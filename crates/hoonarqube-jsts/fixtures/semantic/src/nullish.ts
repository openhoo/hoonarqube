export function nullableText(value: string | undefined, fallback: string): string {
  return value || fallback;
}

export function nullableNumber(value: number | undefined, fallback: number): number {
  return value || fallback;
}

export function nullableObject(value: { count: number } | null, fallback: { count: number }): { count: number } {
  return value || fallback;
}

export function checked(value: number | undefined, fallback: number): number {
  return value !== undefined ? value : fallback;
}

export function sideEffect(read: () => number | undefined, fallback: number): number {
  return read() || fallback;
}
