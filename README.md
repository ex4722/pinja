<h1>PINJA</h1>

Pwn tools is an amazing tool but automating debugger tasks with the API is not the greatest experience. On the other hand Binary Ninja has an amazing debug interface with their DebuggerController class.
This project seeks to combine the two into one class for easiser usage. I don't know what I'm doing so please open a issue if you have anything to say.


<h2>Getting Started</h2>

```python 
from pinja import * 

p = ninja_process("a.out")
# Breaks at entrypoint, must continue
p.go()
print(p.clean())
p.sendline(b"deadbeef")
p.clean()
```
