// Hoonarqube oracle fixture: go:S1151 bad
package oracle

func foo(tag int) {
	switch tag {
	case 0:
		methodCall1()
		methodCall2()
		methodCall3()
		methodCall4()
                methodCall5()
                methodCall6()
	case 1:
		bar()
	}
}
