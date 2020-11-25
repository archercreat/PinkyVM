from pinky.regs import SP_init
from miasm.core.cpu import sign_ext
from miasm.expression.expression import *
from miasm.arch.pinky.regs import *
from miasm.arch.pinky.arch import mn_pinky
from miasm.ir.ir import IntermediateRepresentation


QP = SP
QP_init = SP_init
def loc_key_bitness(loc, bits):
  if not loc.is_loc():
    return loc
  return ExprLoc(loc.loc_key, bits)

def get_main_reg(reg):
  sz = reg.size
  if reg.is_id():
    if sz == 8:
      main_reg = convert8[reg]
    elif sz == 16:
      main_reg = convert16[reg]
    elif sz ==32 :
      main_reg = reg
    else:
      raise RuntimeError
    return main_reg

def mov(_, instr, val, reg):
  if val.is_int():
    e = [ExprAssign(reg, ExprInt(int(val), reg.size))]
  else:
    e = [ExprAssign(reg, val)]
  return e, []

def add(_, instr, reg1, reg2):
  result = reg1 + reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def sub(_, instr, reg1, reg2):
  result = reg1 - reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def mul(_, instr, reg1, reg2):
  result = reg1 * reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def div(_, instr, reg1, reg2):
  result = reg1 / reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def mod(_, instr, reg1, reg2):
  result = reg1 % reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def v_and(_, instr, reg1, reg2):
  result = reg1 & reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def v_or(_, instr, reg1, reg2):
  result = reg1 | reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def xor(_, instr, reg1, reg2):
  result = reg1 ^ reg2
  e = [ExprAssign(reg2, result)]
  return e, []

def jmp(ir, instr, imm):
  if imm.is_loc():
    imm = loc_key_bitness(imm, 32)
  e = []
  e += [ExprAssign(PC, imm)]
  e += [ExprAssign(ir.IRDst, imm)]
  return e, []

def je(ir, instr, reg1, reg2, imm):
  loc_next = ir.get_next_loc_key(instr)
  loc_next_expr = ExprLoc(loc_next, 32)
  e = []

  cmp = ExprOp("FLAG_EQ_CMP", reg1, reg2)
  e += [ExprAssign(PC, ExprCond(cmp, imm, loc_next_expr))]
  e += [ExprAssign(ir.IRDst, ExprCond(cmp, reg1, reg2), imm, loc_next_expr)]
  return e, []
  
def jne(ir, instr, reg1, reg2, imm):
  loc_next = ir.get_next_loc_key(instr)
  loc_next_expr = ExprLoc(loc_next, 32)
  e = []
  imm = loc_key_bitness(imm, 32)
  cmp = ExprOp("FLAG_EQ_CMP", reg1, reg2)
  e += [ExprAssign(PC, ExprCond(cmp, loc_next_expr, imm))]
  e += [ExprAssign(ir.IRDst, ExprCond(cmp, loc_next_expr, imm))]
  return e, []
  
def jge(ir, instr, reg1, reg2, imm):
  loc_next = ir.get_next_loc_key(instr)
  loc_next_expr = ExprLoc(loc_next, 32)
  e = []
  imm = loc_key_bitness(imm, 32)
  cmp = ExprOp("CC_U>=", reg1, reg2)
  e += [ExprAssign(PC, ExprCond(cmp, imm, loc_next_expr))]
  e += [ExprAssign(ir.IRDst, ExprCond(cmp, imm, loc_next_expr))]
  return e, []
  
def jl(ir, instr, reg1, reg2, imm):
  loc_next = ir.get_next_loc_key(instr)
  loc_next_expr = ExprLoc(loc_next, 32)
  e = []
  imm = loc_key_bitness(imm, 32)
  cmp = ExprOp("CC_U<", reg1, reg2)
  e += [ExprAssign(PC, ExprCond(cmp, imm, loc_next_expr))]
  e += [ExprAssign(ir.IRDst, ExprCond(cmp, imm, loc_next_expr))]
  return e, []

def v_str(_, instr, reg):
  e = []
  e += [ExprAssign(ExprMem(SP, SP.size), reg)]
  e += [ExprAssign(SP, ExprOp('+', SP, ExprInt(4, SP.size)))]
  return e, []

def v_strb(_, instr, reg):
  e = []
  e += [ExprAssign(ExprMem(SP, 8), reg[0:8])]
  e += [ExprAssign(SP, ExprOp('+', SP, ExprInt(1, SP.size)))]
  return e, []

def v_strw(_, instr, reg):
  e = []
  e += [ExprAssign(ExprMem(SP, 16), reg[0:16])]
  e += [ExprAssign(SP, ExprOp('+', SP, ExprInt(2, SP.size)))]
  return e, []

def cls(_, instr):
  e =  []
  e += [ExprAssign(SP, SP_init)]
  e += [ExprAssign(QP, QP_init)]
  return e, []

def vmexit(ir, instr):
  e = []
  e += [ExprAssign(PC, ExprId("VMEXIT", 32))]
  e += [ExprAssign(ir.IRDst, ExprId("VMEXIT", 32))]
  return e, []

def read_input(ir, instr, imm):
  e = []
  imm = ExprInt(int(imm), ir.sp.size)
  e += ir.call_effects(ExprId("scanf", 32), imm)
  return e, []

def prn(ir, instr):
  e = []
  e += ir.call_effects(ExprId("puts", 32), ir.qp)
  exprs, _ = cls(ir, instr)
  e += exprs
  return e, []

def ldr(_, instr, reg):
  e = []
  e += [ExprAssign(reg, ExprMem(QP, QP.size))]
  e += [ExprAssign(QP, ExprOp('+', QP, ExprInt(4, QP.size)))]
  return e, []

def ldrb(_, instr, reg):
  e = []
  e += [ExprAssign(reg, ExprMem(QP, 8).zeroExtend(reg.size))]
  e += [ExprAssign(QP, ExprOp('+', QP, ExprInt(1, QP.size)))]
  return e, []

def ldrw(_, instr, reg):
  e = []
  
  e += [ExprAssign(reg, ExprMem(QP, 16)).zeroExtend(reg.size)]
  e += [ExprAssign(QP, ExprOp('+', QP, ExprInt(1, QP.size)))]
  return e, []

mnemo_func = {
    "MOV": mov,
    "ADD": add,
    "SUB": sub,
    "MUL": mul,
    "DIV": div,
    "MOD": mod,
    "AND": v_and,
    "OR": v_or,
    "XOR": xor,
    "JMP": jmp,
    "JE": je,
    "JNE": jne,
    "JGE": jge,
    "JL": jl,
    "STR": v_str,
    "STRB": v_strb,
    "STRW": v_strw,
    "CLS": cls,
    "VMEXIT": vmexit,
    "PRN" : prn,
    "READ_INPUT": read_input,
    "LDR": ldr,
    "LDRB": ldrb,
    "LDRW": ldrw,
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
    self.qp = mn_pinky.getqp()
    self.IRDst = ExprId("IRDst", 32)

  def get_ir(self, instr):
    """Get the IR from a miasm instruction."""
    args = instr.args
    instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
    return instr_ir, extra_ir


  