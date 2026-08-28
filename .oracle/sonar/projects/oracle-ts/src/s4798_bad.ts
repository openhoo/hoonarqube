// S4798 bad: optional boolean parameter without a default.
interface TaskOptions {
  retries: number;
}

function runTask(name: string, verbose?: boolean, options?: TaskOptions): void {}
