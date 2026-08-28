// Hoonarqube oracle fixture: go:S1151 good
package oracle

func foo(tag int) {
	switch tag {
	case 0:
		executeAll()
	case 1:
		bar()
	}
}

func executeAll() {
	methodCall1()
	methodCall2()
	methodCall3()
	methodCall4()
        methodCall5()
        methodCall6()
}
