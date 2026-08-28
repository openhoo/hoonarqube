export const SIMPLE_PATTERN: RegExp = /([a-z]+)/;

export function word(text: string): string | undefined {
  return SIMPLE_PATTERN.exec(text)?.[1];
}
