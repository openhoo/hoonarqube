// Hoonarqube oracle fixture: go:S1821 bad
package oracle

func foo(x,y int) {
	switch x {
	case 0:
		switch y { // Noncompliant; nested switch
		// ...
		}
	case 1:
		// ...
	default:
		// ...
	}
}
