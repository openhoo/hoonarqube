interface Cat {
  meows?: boolean;
}

function isCat(candidate: Cat): boolean {
  return (candidate as Cat).meows !== undefined;
}

const pickles: Cat = { meows: true };
if (isCat(pickles)) {
  console.log(pickles);
}
