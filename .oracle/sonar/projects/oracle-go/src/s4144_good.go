// Hoonarqube oracle fixture: go:S4144 good
package oracle

func fun1() (x, y int) {
  a, b := 1, 2
  b, a = a, b
  return a, b
}

func fun2() (x, y int) {  // Intent is clear
  return fun1()
}
