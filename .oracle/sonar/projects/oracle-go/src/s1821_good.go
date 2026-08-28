// Hoonarqube oracle fixture: go:S1821 good
package oracle

func foo(x,y int) {
	switch x {
	case 0:
		bar(y)
	case 1:
		// ...
	default:
		// ...
	}
}

func bar(y int) {
	switch y {
	// ...
	}
}
