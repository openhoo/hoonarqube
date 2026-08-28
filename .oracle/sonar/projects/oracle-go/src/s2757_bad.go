// Hoonarqube oracle fixture: go:S2757 bad
package oracle
func update(target, value int) int { target =- value; target =+ value; return target }
