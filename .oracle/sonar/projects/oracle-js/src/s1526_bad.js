function f() {
  console.log(hoisted);
  var hoisted = 1;
}
f();
