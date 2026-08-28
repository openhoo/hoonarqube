// Hoonarqube oracle fixture: go:S1186 good
package oracle

func shouldNotBeEmpty() {
  doSomething();
}

func notImplemented() {
  return "", errors.New("notImplemented() cannot be performed because ...")
}

func emptyOnPurpose() {
  // comment explaining why the method is empty
}
