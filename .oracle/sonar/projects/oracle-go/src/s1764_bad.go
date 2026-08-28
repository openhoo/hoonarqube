// Hoonarqube oracle fixture: go:S1764 bad
package oracle

func main() {
  v1 := (true && false) && (true && false) // Noncompliant
}
