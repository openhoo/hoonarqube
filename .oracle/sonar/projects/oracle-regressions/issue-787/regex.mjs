export function isUnsafeSlug(value) {
  return /^((a+)+)+$/.test(
    value,
  );
}
