// Hoonarqube oracle fixture: go:S1192 good
package oracle

const ACTION = "This should be a constant"

func run() {
	prepare(ACTION)
	execute(ACTION)
	release(ACTION)
}
