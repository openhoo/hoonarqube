def finish(task):
    task.run()
    return

for item in items:
    process(item)
    continue

while pending():
    poll()
    continue

match mode:
    case "stop":
        halt()
        break
