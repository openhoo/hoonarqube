// Hoonarqube oracle fixture: go:S1192 bad
package oracle

func run() {
	prepare("This should be a constant")  // Noncompliant; 'This should ...' is duplicated 3 times
	execute("This should be a constant")
	release("This should be a constant")
}
