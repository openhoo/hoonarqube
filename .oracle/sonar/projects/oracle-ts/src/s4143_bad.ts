function f(map) {
  const current = map.get('key');
  map.set('key', current);
}
f(m);
