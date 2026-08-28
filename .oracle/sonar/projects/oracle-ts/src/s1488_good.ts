function fail() {
  throw new Error('boom');
}

function scale(value) {
  const scaled = wrap(value);
  return scaled + 1;
}
