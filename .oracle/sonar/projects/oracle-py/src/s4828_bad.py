import os
import signal

signal.signal(9, handler)
os.kill(pid, 15)
