// Hoonarqube oracle fixture: go:S1763 bad
package oracle

func add(x, y int) int {
	return x + y // Noncompliant
	z := x + y // dead code
}
