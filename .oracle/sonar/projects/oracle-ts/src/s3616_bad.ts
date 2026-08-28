function classify(value) {
  switch (value) {
    case 1 || 2:
      return 'low';
    case 3:
      return 'mid';
    case 4:
      return 'high';
    default:
      return 'other';
  }
}
