// Hoonarqube oracle fixture: go:S1871 bad
package oracle
func choose(a int) {
 if a < 10 {
  println(1)
  println(2)
 } else if a < 20 {
  println(3)
 } else if a < 30 {
  println(1)
  println(2)
 } else {
  println(4)
 }
}
