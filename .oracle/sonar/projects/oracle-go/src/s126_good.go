// Hoonarqube oracle fixture: go:S126 good
package oracle

import "errors"

func completeSelection(x int) error {
	if x == 0 {
		doSomething()
	} else if x == 1 {
		doSomethingElse()
	} else {
		return errors.New("unsupported int")
	}
	return nil
}
