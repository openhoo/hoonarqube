// Hoonarqube oracle fixture: go:S1862 bad
package oracle

func example(condition1, condition2 bool) {
  if condition1 {
  } else if condition1 { // Noncompliant
  }
}
