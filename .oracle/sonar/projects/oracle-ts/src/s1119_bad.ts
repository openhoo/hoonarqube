function scan(items) {
  outer: for (const item of items) {
    if (item === 'end') {
      break outer;
    }
  }
}
