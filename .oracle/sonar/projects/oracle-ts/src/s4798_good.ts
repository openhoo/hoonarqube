// S4798 good: optional boolean carries a default value.
interface TaskOptions {
  retries: number;
}

function runTask(
  name: string,
  verbose: boolean = false,
  options: TaskOptions = { retries: 1 },
): void {}
