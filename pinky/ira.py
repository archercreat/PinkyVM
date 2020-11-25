from miasm.ir.analysis import ira
from miasm.arch.pinky.sem import ir_pinky
from miasm.expression.expression import *

class ir_a_pinky(ir_pinky, ira):
  
  def get_out_regs(self, _):
    return set([self.ret_reg, self.sp])