// Hoonarqube oracle fixture: go:S1314 bad
package oracle

func printTen() {
	myNumber := 010 // Noncompliant. myNumber will hold 8, not 10 - was this really expected?
	fmt.Println(myNumber)
}
