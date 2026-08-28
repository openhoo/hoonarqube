// Hoonarqube oracle fixture: go:S1110 bad
package oracle

func foo(a bool, y int) int {
  x := ((y / 2 + 1)) // Noncompliant

  if a && ((x+y > 0)) {  // Noncompliant
    return ((x + 1))  // Noncompliant
  }
}
