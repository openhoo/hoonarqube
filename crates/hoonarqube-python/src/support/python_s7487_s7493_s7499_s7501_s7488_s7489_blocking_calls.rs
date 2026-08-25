// --- python:S7487 / S7493 / S7499 / S7501 / S7488 / S7489 — blocking calls

pub(crate) const SYNC_OS_CALLS: [&str; 9] = [
    "os.system",
    "os.popen",
    "os.fork",
    "os.forkpty",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.posix_spawn",
];

pub(crate) const SYNC_FILE_CALLS: [&str; 10] = [
    "open",
    "io.open",
    "os.open",
    "os.read",
    "os.write",
    "os.remove",
    "os.rename",
    "os.listdir",
    "os.makedirs",
    "os.mkdir",
];

pub(crate) const ASYNC_FILE_METHODS: [&str; 4] =
    ["read_text", "read_bytes", "write_text", "write_bytes"];

pub(crate) const SYNC_HTTP_CALLS: [&str; 19] = [
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.options",
    "httpx.request",
    "httpx.Client",
    "urllib.request.urlopen",
];
