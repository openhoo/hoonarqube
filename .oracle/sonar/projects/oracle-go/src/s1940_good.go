// Hoonarqube oracle fixture: go:S1940 good
package oracle

func compare(a, i int) bool {
	if a != 2 {
		println("different")
	} else {
		println("same")
	}
	b := i >= 10
	return b
}
