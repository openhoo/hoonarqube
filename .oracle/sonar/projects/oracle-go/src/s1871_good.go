// Hoonarqube oracle fixture: go:S1871 good
package oracle

if (a >= 0 && a < 10) || (a >= 20 && a < 50) {
	doFirstThing()
	doSomething()
} else if a >= 10 && a < 20 {
	doSomethingElse()
} else {
	doTheRest()
}
