def sibling(kind):
    if kind == '(':
        value = make()
        yield value
        return
    elif kind == '[':
        yield value


def earlier_read():
    print(value)
    value = 2


def omitted_branch(flag):
    if flag:
        value = 2
    return value


def earlier_value(flag):
    value = 1
    if flag:
        value = 2
    else:
        print(value)


def terminated_path(flag):
    if flag:
        value = 2
        return 'done'
    return value


def closure():
    def child():
        return value
    value = 2
    return child()


def local_builtin():
    print(list)
    list = 2


def parameter(value, flag):
    if flag:
        value = 2
    else:
        yield value


def self_assignment():
    value = value + 1


def later_import():
    print(path)
    from os import path


def loop_carried(values):
    for item in values:
        print(value)
        value = item


def use_after_del():
    value = 1
    del value
    print(value)


def before_annotation():
    value: int
    print(value)


def valid_yield(flag):
    if flag:
        value = 1
        yield value
    else:
        yield 2
