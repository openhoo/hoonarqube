try {
  fetch(url);
  client.then(r => r.json());
  await fetch(other);
} catch (e) {
  log(e);
}
