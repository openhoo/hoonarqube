class SwitchEntry {
    int liveAfterReturn(int key) {
        int value = key + 12;
        switch (key) {
            case 0:
                return -1;
            default:
                return value;
        }
    }

    int liveAfterBreak(int key) {
        int value = key + 12;
        int result = 0;
        switch (key) {
            case 0:
                break;
            case 1:
                result = value;
                break;
            default:
                result = -1;
        }
        return result;
    }

    int liveOnEntryAndFallthrough(int key) {
        int value = key + 12;
        switch (key) {
            case 0:
                value = key + 23;
            case 1:
                return value;
            default:
                return -1;
        }
    }

    int deadOnEntryAndFallthrough(int key) {
        int value = key + 12;
        switch (key) {
            case 0:
                value = key + 23;
            default:
                value = key + 34;
                return value;
        }
    }

    int liveArrowArm(int key) {
        int value = key + 12;
        switch (key) {
            case 0 -> { return -1; }
            default -> { return value; }
        }
    }
}
