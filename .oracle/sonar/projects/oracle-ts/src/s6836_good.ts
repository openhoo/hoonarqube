function describe(value) {
  switch (value) {
    case 1:
      describeOne();
      break;
    case 2: {
      let label = labelFor(2);
      describeLabel(label);
      break;
    }
    case 3:
      describeThree();
      break;
    default:
      break;
  }
}
