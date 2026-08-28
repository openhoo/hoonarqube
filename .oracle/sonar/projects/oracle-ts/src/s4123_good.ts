async function load() {
  return fetch(url);
}
async function main() {
  const value = await load();
}
