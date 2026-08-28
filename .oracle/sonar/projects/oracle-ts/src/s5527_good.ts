function fetchSecure(https, target) {
  return https.get(target, { rejectUnauthorized: true });
}
