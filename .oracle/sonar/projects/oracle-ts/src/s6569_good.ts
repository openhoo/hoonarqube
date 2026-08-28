function identity<T extends { id: string }>(value: T): T {
  return value;
}
