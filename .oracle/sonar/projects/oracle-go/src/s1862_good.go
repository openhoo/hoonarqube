// Hoonarqube oracle fixture: go:S1862 good
package oracle

func SwitchWithMultipleConditions(param int) {
  switch param {
  case 1, 2, 3:
    fmt.Println(">1")
  case 3, 4, 5: // Noncompliant; 3 is duplicated
    fmt.Println("<1")
  }
}
