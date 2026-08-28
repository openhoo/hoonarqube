let more = true;
const input = '42';
while (more) {
  if (/\d+/.test(input)) {
    more = false;
  }
}
