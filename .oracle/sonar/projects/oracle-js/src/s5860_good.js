export const SIMPLE_PATTERN = /([a-z]+)/;

export function word(text) {
  return SIMPLE_PATTERN.exec(text)?.[1];
}
