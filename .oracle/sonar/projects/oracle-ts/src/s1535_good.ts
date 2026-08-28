for (const k in obj) {
  if (obj.hasOwnProperty(k)) {
    f(k);
  }
}
