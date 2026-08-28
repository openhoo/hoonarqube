// Hoonarqube oracle fixture: go:S1125 bad
package oracle
func check(x bool) bool { if x || false { return true }; return x && true }
