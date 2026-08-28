function route(outer, inner) {
  switch (outer) {
    case 1:
      switch (inner) {
        case 'a':
          handleA();
          break;
        case 'b':
          handleB();
          break;
        case 'c':
          handleC();
          break;
        default:
          break;
      }
      break;
    case 2:
      handleTwo();
      break;
    case 3:
      handleThree();
      break;
    default:
      break;
  }
}
