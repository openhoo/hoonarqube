function f(map) {
  const current = map.get('key');
  map.set('other', current);
}
f(m);
