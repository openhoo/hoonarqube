function pickFirst(x) {
  switch (x) {
    case 1:
      doOne();
      break;
    case 2:
      doTwo();
      break;
    case 3:
      doThree();
      break;
    default:
      break;
  }
}

function pickSecond(y) {
  switch (y) {
    case 'a':
      return 'alpha';
    case 'b':
      return 'beta';
    case 'c':
      return 'gamma';
    default:
      return 'other';
  }
}
