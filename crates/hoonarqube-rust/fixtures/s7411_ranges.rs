// Independent compiled range controls. Unicode context: Äλ🦉.
pub fn prefix_one(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 1;
        value += 2;
    } else {
        value += 1;
        value += 3;
    }
    value
}

pub fn prefix_many(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 1;
        value *= 2;
        value += 3;
    } else {
        value += 1;
        value *= 2;
        value += 4;
    }
    value
}

pub fn suffix_one(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 2;
        value += 1;
    } else {
        value += 3;
        value += 1;
    }
    value
}

pub fn suffix_many(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 2;
        value += 1;
        value *= 3;
    } else {
        value += 4;
        value += 1;
        value *= 3;
    }
    value
}

pub fn both_ends(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 1;
        value += 2;
        value *= 4;
    } else {
        value += 1;
        value += 3;
        value *= 4;
    }
    value
}

pub fn multiple_branches(first: bool, second: bool, mut value: i32) -> i32 {
    if first {
        value += 1;
        value += 2;
    } else if second {
        value += 1;
        value += 3;
    } else {
        value += 1;
        value += 4;
    }
    value
}

pub fn distinct(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 1;
    } else {
        value += 2;
    }
    value
}

pub fn identical(flag: bool, mut value: i32) -> i32 {
    if flag {
        value += 1;
    } else {
        value += 1;
    }
    value
}

pub fn local_bindings(flag: bool) -> i32 {
    if flag {
        let value = 1;
        value + 1
    } else {
        let value = 2;
        value + 1
    }
}
