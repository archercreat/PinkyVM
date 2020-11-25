from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.ir.symbexec import *
from miasm.arch.spacez.regs import regs_init
import logging
from miasm.analysis.cst_propag import *

# logger = logging.getLogger('asmblock')

# logger.setLevel(logging.DEBUG)

def save_ircfg(ircfg, name: str) -> None:
  import subprocess
  open(name, 'w').write(ircfg.dot())
  subprocess.call(["dot", "-Tpng", name, "-o", "test.png"])
  subprocess.call(["rm", name])

fdesc = open("bytecode", 'rb')
loc_db = LocationDB()

raw = fdesc.read()
machine = Machine("pinky")
mdis = machine.dis_engine(raw, loc_db=loc_db)

addr = 0
asmcfg = mdis.dis_multiblock(addr)
save_ircfg(asmcfg, "test.dot")