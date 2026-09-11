// Hoonarqube oracle fixture: go:S134 good
package oracle

func nestedFlow(condition1, condition2, condition4, condition5 bool) {
	if !condition1 {
		return
	}
	if !condition2 {
		return
	}
	for i := 1; i <= 10; i++ {
		println(i)
		if condition4 {
			if condition5 {
				println("nested")
			}
			return
		}
	}
}
