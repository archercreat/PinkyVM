from pinky.regs import SP_init
from miasm.core.cpu import sign_ext
from miasm.expression.expression import *
from miasm.arch.pinky.regs import *
from miasm.arch.pinky.arch import mn_pinky
from miasm.ir.ir import IntermediateRepresentation

def update_flag_zf(a):
  return [ExprAssign(ZF, ExprOp("FLAG_EQ", a))]

def update_flag_zf_eq(a, b):
    return [ExprAssign(ZF, ExprOp("FLAG_EQ_CMP", a, b))]

def mov(_, instr, dst, src):
  e = []
  if src.is_int() and src.size == 16:
    # mov0
    e += [ExprAssign(dst, ExprInt(int(src), dst.size))]
  elif instr.name == 'MOV3':
    e += [ExprAssign(src, dst)]
  else:
    # mov1
    e += [ExprAssign(dst, src)]
  return e, []

def add(_, instr, dst, src1, src2):
  result = src1 + src2
  e = [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def sub(_, instr, dst, src1, src2):
  result = src1 - src2
  e = [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def mul(_, instr, dst, src1, src2):
  result = src1 * src2
  e = [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def div(_, instr, dst, src1, src2):
  result = src1 / src2
  e = [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def v_and(_, instr, dst, src1, src2):
  result = src1 & src2
  e = [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def v_or(_, instr, dst, src1, src2):
  result = src1 | src2
  e = [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def xor(_, instr, dst, src1, src2):
  e = []
  result = src1 ^ src2
  e += [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, ExprInt(0, dst.size))
  return e, []

def inc(ir, instr, dst):
  e      = []
  src    = ExprInt(1, dst.size)
  null   = ExprInt(0, dst.size)
  result = dst + src
  e += [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, null)
  return e, []

def dec(ir, instr, dst):
  e      = []
  src    = ExprInt(1, dst.size)
  null   = ExprInt(0, dst.size)
  result = dst - src
  e += [ExprAssign(dst, result)]
  e += update_flag_zf_eq(result, null)
  return e, []

def jmp(ir, instr, dst):
  e = []
  if dst.is_int():
    dst = ExprInt(dst, PC.size)
  elif dst.is_loc():
    dst = ExprLoc(dst.loc_key, PC.size)

  e += [ExprAssign(PC, dst)]
  e += [ExprAssign(ir.IRDst, dst)]
  return e, []

def je(ir, instr, dst):
  e = []
  if dst.is_int():
    dst = ExprInt(dst, PC.size)
  elif dst.is_loc():
    dst = ExprLoc(dst.loc_key, PC.size)

  loc_next = ir.get_next_loc_key(instr)
  loc_next_expr = ExprLoc(loc_next, ir.IRDst.size)
  e += [ExprAssign(PC, ExprCond(ZF, dst, loc_next_expr))]
  e += [ExprAssign(ir.IRDst, ExprCond(ZF, dst, loc_next_expr))]
  return e, []

def jne(ir, instr, dst):
  e = []
  if dst.is_int():
    dst = ExprInt(dst, PC.size)
  elif dst.is_loc():
    dst = ExprLoc(dst.loc_key, PC.size)

  loc_next = ir.get_next_loc_key(instr)
  loc_next_expr = ExprLoc(loc_next, ir.IRDst.size)
  e += [ExprAssign(PC, ExprCond(ZF, loc_next_expr, dst))]
  e += [ExprAssign(ir.IRDst, ExprCond(ZF, loc_next_expr, dst))]
  return e, []

def cmp(ir, instr, dst, src):
  e = []
  if src.is_int():
    src = ExprInt(int(src), dst.size)
  result = dst - src
  null = ExprInt(0, dst.size)
  e += update_flag_zf_eq(result, null)
  return e, []

def ret(ir, instr):
  e = []
  e += [ExprAssign(PC, ExprId('VMEXIT', PC.size))]
  e += [ExprAssign(ir.IRDst, ExprId('VMEXIT', ir.IRDst.size))]
  return e, []

def nop(ir, instr):
  return [], []

mnemo_func = {
    "MOV": mov,
    "MOV1": mov,
    "MOV2": mov,
    "MOV3": mov,
    "ADD": add,
    "SUB": sub,
    "MUL": mul,
    "DIV": div,
    "INC": inc,
    "DEC": dec,
    "AND": v_and,
    "OR":  v_or,
    "XOR": xor,
    "JMP": jmp,
    "JE":  je,
    "JNE": jne,
    "CMP": cmp,
    "RET": ret,
    "NOP": nop
}


class ir_pinky(IntermediateRepresentation):
  """Toshiba MeP miasm IR - Big Endian
      It transforms an instructon into an IR.
  """
  addrsize = 32

  def __init__(self, loc_db=None):
    IntermediateRepresentation.__init__(self, mn_pinky, None, loc_db)
    self.pc = mn_pinky.getpc()
    self.sp = mn_pinky.getsp()
    self.ret_reg = EAX
    self.IRDst = ExprId("IRDst", 32)

  def get_ir(self, instr):
    """Get the IR from a miasm instruction."""
    args = instr.args
    instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
    return instr_ir, extra_ir