let more = true;
const input = '42';
while (more) {
  if (/\d+/g.test(input)) {
    more = false;
  }
}
