interface Cat {
  meows: boolean;
}

function isCat(candidate: Cat): candidate is Cat {
  return candidate.meows;
}

const pickles: Cat = { meows: true };
if (isCat(pickles)) {
  console.log(pickles);
}
