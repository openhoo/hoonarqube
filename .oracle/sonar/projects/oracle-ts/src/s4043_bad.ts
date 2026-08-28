function f(list) {
  const sorted = list.sort();
  return list.length + sorted.length;
}
f(items);
