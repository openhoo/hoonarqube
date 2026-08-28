import os
import subprocess

os.system("ls -la")
os.popen("id")
subprocess.getoutput("whoami")
subprocess.run("ls", shell=True)
