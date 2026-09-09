// Hoonarqube oracle fixture: go:S1125 good
package oracle

func useBoolean(boolValue, x bool) bool {
	if boolValue {
		println("enabled")
	} else {
		println("disabled")
	}
	flag := x
	return flag
}
