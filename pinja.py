from unittest.mock import Mock
from os import system
from binaryninja.debugger import DebuggerController
import binaryninja
import pwn
from pwnlib.util import packing

class ninja_process(pwn.process):
    def __init__(self, filename):
        """
        exe is pwn ELF object 
        filename is patched binary location 
        bv is BN live view of process
        dbg is BN DebuggerController
        """

        self.exe = pwn.ELF(filename)
        self.exe.asm(self.exe.entrypoint, "h: jmp h;nop;nop")
        self.exe.save("/tmp/" + filename)

        self.filename =  "/tmp/" + filename
        system(f"chmod +x {self.filename}")


        bv  = binaryninja.BinaryViewType.get_view_of_file(filename)
        self.dbg = DebuggerController(bv)

        super().__init__(self.filename)

        if self.dbg.attach(self.pid):
            pwn.info(f"Sucessfully Attached to process {self.pid}")
        else:
            pwn.error(f"Error Attaching to process {self.pid}")

        self.bv = self.dbg.live_view 

        # atat bad
        self.dbg.execute_backend_command("settings set target.x86-disassembly-flavor intel")

        self.dbg.set_reg_value("rip", self.bv.entry_point +4)
        self.bv.write(self.bv.entry_point, pwn.asm("endbr64"))

        # Clones the BN debugger object, hopefully no name collisions
        # for attr in [method_name for method_name in dir(self.dbg) if not method_name.startswith('__') and method_name != 'ID']:
        # for attr in [method_name for method_name in dir(self.dbg) if not method_name.startswith("_") ]:
        #     setattr(self,attr,  (getattr(self.dbg, attr)))

        # self.breakpoints = DebuggerController.breakpoints 

    def __getattr__(self, attr):
        try:
            return getattr(self.dbg, attr)
        except:
            return super().__getattr__(attr)

    def sendline(self, line=b''):
        # Screw \n, If you want a newline put it in urself
        line = packing._need_bytes(line)
        self.send(line)

    def close(self): 
        super().close()
        self.bv.file.close()
        self.dbg.destroy()

    def pause(self):
        if self.target_status.value == 1:
            self.execute_backend_command("process interrupt")
            return True
        else:
            # Already pause/breakpoint
            return False


    # Custom Binja Stuff, mirrors gdb
    def add_breakpoint_sym(self, symbol : str):
        if "+" in symbol:
            symbol = symbol.split("+")
            self.add_breakpoint( self.bv.symbols[symbol[0]][0].address + int(symbol[1]))
        else:
            self.add_breakpoint( self.bv.symbols[symbol][0].address )





# Mock everything
def fake_debug(*args,**kwargs):
    d = pwn.gdb.debug(args,**kwargs)
    # No need to comment between flips
    for attr in [method_name for method_name in dir(DebuggerController) if not method_name.startswith("_") ]:
        setattr(d, attr, Mock())
    d.dbg = Mock()
    d.bv = Mock()
    return d 
