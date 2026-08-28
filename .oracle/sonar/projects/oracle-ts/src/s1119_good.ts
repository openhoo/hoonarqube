function scan(items) {
  for (const item of items) {
    if (item === 'end') {
      return 'found';
    }
  }
  return 'missing';
}
