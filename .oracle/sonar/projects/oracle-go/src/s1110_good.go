// Hoonarqube oracle fixture: go:S1110 good
package oracle

func foo(a bool, y int) int {
  x := (y / 2 + 1)

  if a && (x+y > 0) {
    return (x + 1)
  }
}
