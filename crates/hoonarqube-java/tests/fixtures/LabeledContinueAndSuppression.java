class LabeledContinueAndSuppression {
    int plainContinueInLabeledWhile(int limit) {
        int pos = 0;
        scan: while (pos < limit) {
            pos += 2;
            continue;
        }
        return pos;
    }

    int plainContinueInSwitch(int input) {
        int state = 2;
        scan: for (int i = 0; i < input; i++) {
            switch (i) {
                case 0:
                    state = 3;
                    continue;
                default:
                    if (state == 3) {
                        return state;
                    }
            }
        }
        return 0;
    }

    void namedContinueAcrossLoops(int limit) {
        int outerIndex = 0;
        outer: while (outerIndex < limit) {
            inner: for (int i = 0; i < limit; i++) {
                outerIndex = 3;
                continue outer;
            }
            return;
        }
    }

    int nextName() {
        return 7;
    }

    void deliberatelyDiscarded() {
        @SuppressWarnings("unused")
        int discarded = nextName();
        @java.lang.SuppressWarnings(value = {"deprecation", "java:S1854"})
        int ignored = nextName();
        @SuppressWarnings("deprecation")
        int unrelated = nextName();
        int unsuppressed = nextName();
        @java.lang.SuppressWarnings("unused")
        int qualified = nextName();
        @SuppressWarnings({"deprecation", "java:S1854"})
        int array = nextName();
        @SuppressWarnings(value = "unused")
        int named = nextName();
    }
}
