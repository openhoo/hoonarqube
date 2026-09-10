// Hoonarqube oracle fixture: go:S1067 good
package oracle

func checkConditions() {
	if (myFirstCondition() || mySecondCondition()) && myLastCondition() {
		println("conditions met")
	}
}
