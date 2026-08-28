// Hoonarqube oracle fixture: go:S126 good
package oracle

if x == 0 {
	doSomething()
} else if x == 1 {
	doSomethingElse()
} else {
	return errors.New("unsupported int")
}
