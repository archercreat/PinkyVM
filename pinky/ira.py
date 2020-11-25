from miasm.ir.analysis import ira
from miasm.arch.pinky.sem import ir_pinky
from miasm.expression.expression import *

class ir_a_pinky_base(ir_pinky, ira):

  def __init__(self, loc_db):
    ir_pinky.__init__(self, loc_db)
    self.ret_reg = self.arch.regs.R0

  def call_effects(self, addr, *args):
    call_assignblk = [
            ExprAssign(self.ret_reg, ExprOp('call_func', addr, *args)),
    ]
    return call_assignblk

class ir_a_pinky(ir_a_pinky_base):

  def __init__(self, loc_db):
      ir_a_pinky_base.__init__(self, loc_db)

  def get_out_regs(self, _):
      return set([self.ret_reg, self.sp])