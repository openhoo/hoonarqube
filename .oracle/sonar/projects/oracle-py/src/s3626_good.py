def finish(task):
    if task.failed:
        return 1
    return 0

for item in items:
    if item is None:
        continue
    process(item)

while pending():
    if skipped():
        break
    poll()

match mode:
    case "stop":
        halt()
