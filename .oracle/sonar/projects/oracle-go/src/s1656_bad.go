// Hoonarqube oracle fixture: go:S1656 bad
package oracle

func (user *User) rename(name string) {
  name = name  // Noncompliant
}
