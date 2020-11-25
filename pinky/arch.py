from miasm.core.cpu import *
from miasm.core.utils import Disasm_Exception
from miasm.expression.expression import ExprId, ExprInt, ExprLoc, \
    ExprMem, ExprOp, is_expr
from miasm.core.asm_ast import AstId, AstMem
from miasm.arch.pinky.regs import *
import miasm.arch.pinky.regs as pinky_regs_module
from pyparsing import *

conditional_branch = [
  "JE", "JNE"
]
unconditional_branch  = ["JMP"]

breakflow = ["VMEXIT"] + conditional_branch + unconditional_branch + ["RET"]

LBRACK = Suppress("[")
RBRACK = Suppress("]")
DWORD = Literal('DWORD')

def cb_deref_base_expr(tokens):
  print('TOKENS', tokens)
  tokens = tokens[0]
  assert isinstance(tokens, AstNode)
  addr = tokens
  return addr

deref_reg = (LBRACK + base_expr + RBRACK).setParseAction(cb_deref_base_expr)

class instruction_pinky(instruction):
  """Generic pinky instruction
  Notes:
      - this object is used to build internal miasm instructions based
        on mnemonics
      - it must be implemented !
  """

  # Default delay slot
  # Note:
  #   - mandatory for the miasm Machine
  delayslot = 0

  def __init__(self, name, mode, args, additional_info=None):
    self.name = name
    self.mode = mode
    self.args = args
    self.additional_info = additional_info
    self.offset = None
    self.l = None
    self.b = None    

  @staticmethod
  def arg2str(expr, pos=None, loc_db=None):
      """Convert mnemonics arguments into readable strings according to the
      pinky architecture and their internal types
      """

      if isinstance(expr, ExprId) or isinstance(expr, ExprInt):
          return str(expr)

      elif isinstance(expr, ExprLoc):
          if loc_db is not None:
              return loc_db.pretty_str(expr.loc_key)
          else:
              return str(expr)
      return str(expr)

  def to_string(self, loc_db=None):
    # mov reg1, @[reg2] -> mov @[reg2], reg1
    if self.name == 'MOV' and self.args[1].is_mem() and self.args[1].ptr.is_id():
      self.args[1], self.args[0] = self.args[0], self.args[1]
    return super(instruction_pinky, self).to_string(loc_db)

  def breakflow(self):
    """Instructions that stop a basic block."""
    if self.name in breakflow:
      return True
    return False

  def splitflow(self):
    """Instructions that splits a basic block, i.e. the CPU can go somewhere else."""
    if self.name in conditional_branch:
      return True
    return False

  def dstflow(self):
    """Instructions that explicitly provide the destination."""
    if self.name in conditional_branch + unconditional_branch:
      return True
    return False

  def dstflow2label(self, loc_db):
    """Set the label for the current destination.
        Note: it is used at disassembly"""
    loc_arg = self.get_dst_num()
    expr = self.args[loc_arg]
    if not expr.is_int():
      return
    # mega hack we add 2 because imm16 is 2 bytes
    addr = (int(expr) + self.offset + 2) & int(expr.mask)
    loc_key = loc_db.get_or_create_offset_location(addr)
    self.args[loc_arg] = ExprLoc(loc_key, expr.size)

  def getdstflow(self, loc_db):
    """Get the argument that points to the instruction destination."""
    if self.name in conditional_branch + unconditional_branch:
      return [self.args[self.get_dst_num()]]
    raise RuntimeError

  def is_subcall(self):
    """
    Instructions used to call sub functions.
    pinky Does not have calls.
    """
    return False

  def get_dst_num(self):
    return 0

class pinky_additional_info(object):
  """Additional pinky instructions information
  """

  def __init__(self):
    self.except_on_instr = False

class mn_pinky(cls_mn):
  num = 0  # holds the number of mnemonics
  all_mn = list()  # list of mnenomnics, converted to metamn objects
  all_mn_mode = defaultdict(list) # mneomnics, converted to metamn objects
  all_mn_name = defaultdict(list) # mnenomnics strings
  all_mn_inst = defaultdict(list) # mnemonics objects
  bintree = dict()  # Variable storing internal values used to guess a
  instruction = instruction_pinky
  regs = pinky_regs_module
  max_instruction_len = 6
  delayslot = 0
  name = "pinky"

  def additional_info(self):
    return pinky_additional_info()

  @classmethod
  def gen_modes(cls, subcls, name, bases, dct, fields):
    dct["mode"] = None
    return [(subcls, name, bases, dct, fields)]

  @classmethod
  def getmn(cls, name):
    return name.upper()

  @classmethod
  def getpc(cls, attrib=None):
    """"Return the ExprId that represents the Program Counter.
    Notes:
        - mandatory for the symbolic execution
        - PC is defined in regs.py
    """
    return PC

  @classmethod
  def getsp(cls, attrib=None):
    """"Return the ExprId that represents the Stack Pointer.
    Notes:
        - mandatory for the symbolic execution
        - SP is defined in regs.py
    """
    return SP

def addop(name, fields, args=None, alias=False):
  """
  Dynamically create the "name" object
  Notes:
      - it could be moved to a generic function such as:
        addop(name, fields, cls_mn, args=None, alias=False).
      - most architectures use the same code
  Args:
      name:   the mnemonic name
      fields: used to fill the object.__dict__'fields' attribute # GV: not understood yet
      args:   used to fill the object.__dict__'fields' attribute # GV: not understood yet
      alias:  used to fill the object.__dict__'fields' attribute # GV: not understood yet
  """

  namespace = {"fields": fields, "alias": alias}

  if args is not None:
      namespace["args"] = args

  # Dynamically create the "name" object
  type(name, (mn_pinky,), namespace)

class pinky_arg(m_arg):
  def asm_ast_to_expr(self, arg, loc_db):
    """Convert AST to expressions
       Note: - Must be implemented"""

    if isinstance(arg, AstId):
      if isinstance(arg.name, ExprId):
        return arg.name
      if isinstance(arg.name, str) and arg.name in gpr_names:
        return None  # GV: why?
      loc_key = loc_db.get_or_create_name_location(arg.name.encode())
      return ExprLoc(loc_key, 32)

    elif isinstance(arg, AstMem):
      addr = self.asm_ast_to_expr(arg.ptr, loc_db)
      if addr is None:
        return None
      return ExprMem(addr, 32)

    elif isinstance(arg, AstInt):
      return ExprInt(arg.value, 32)

    elif isinstance(arg, AstOp):
      args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
      if None in args:
          return None
      return ExprOp(arg.op, *args)

    # Raise an exception if the argument was not processed
    message = "mep_arg.asm_ast_to_expr(): don't know what \
                to do with a '%s' instance." % type(arg)
    raise Exception(message)

class pinky_reg(reg_noarg, pinky_arg):
  """Generic pinky register
  Note:
      - the register size will be set using bs()
  """
  reg_info = gpr_infos  # the list of pinky registers defined in regs.py
  parser = reg_info.parser  # GV: not understood yet

class pinky_reg_deref(pinky_arg):
  parser = deref_reg
  reg_info = gpr_infos  # the list of pinky registers defined in regs.py

  def decode(self, v):
    v = v & self.lmask
    if v >= len(self.reg_info.expr):
      return False
    self.expr = self.reg_info.expr[v]
    self.expr = ExprMem(self.expr, self.expr.size)
    return True


class pinky_imm8(imm_noarg, pinky_arg):
  """Generic pinky immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 8
  intmask = (1 << intsize) - 1
  parser = base_expr

class pinky_imm16(imm_noarg, pinky_arg):
  """Generic pinky immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 16
  intmask = (1 << intsize) - 1
  parser = base_expr

  def decodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

  def encodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

class pinky_imm32(imm_noarg, pinky_arg):
  """Generic pinky immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 32
  intmask = (1 << intsize) - 1
  parser = base_expr

  def decodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

  def encodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

reg   = bs(l=8,   cls=(pinky_reg, ))
reg_deref = bs(l=8, cls=(pinky_reg_deref,))
imm8  = bs(l=8,   cls=(pinky_imm8,  pinky_arg))
imm16 = bs(l=16,  cls=(pinky_imm16, pinky_arg))
imm32 = bs(l=32,  cls=(pinky_imm32, pinky_arg))

addop("VMEXIT", [bs("00000000")])                 # 0
addop("MOV",    [bs("00000001"), reg, imm16])     # 1
# addop("PRNHEX", [bs("00000010"), reg])            # 2
# addop("STR2INT",[bs("00000011"), reg])            # 3
# addop("RAND",   [bs("00000100"), reg])            # 4
addop("JMP",    [bs("00010000"), imm16])          # 16
addop("JE" ,    [bs("00010001"), imm16])          # 17
addop("JNE",    [bs("00010010"), imm16])          # 18
addop("XOR",    [bs("00100000"), reg, reg, reg])  # 32
addop("ADD",    [bs("00100001"), reg, reg, reg])  # 33
addop("SUB",    [bs("00100010"), reg, reg, reg])  # 34
addop("MUL",    [bs("00100011"), reg, reg, reg])  # 35
addop("DIV",    [bs("00100100"), reg, reg, reg])  # 36
addop("INC",    [bs("00100101"), reg])            # 37
addop("DEC",    [bs("00100110"), reg])            # 38
addop("AND",    [bs("00100111"), reg, reg, reg])  # 39
addop("OR",     [bs("00101000"), reg, reg, reg])  # 40
# addop("IDK0",   [bs("00110000"), reg])            # 48
# addop("PRNSTR", [bs("00110001"), reg])            # 49
# addop("SPRNTF", [bs("00110010"), reg, reg, reg])  # 50
# addop("SYSTEM", [bs("00110011"), reg])            # 51
# addop("ATOI",   [bs("00110100"), reg])            # 52
addop("CMP",    [bs("01000000"), reg, reg])       # 64
addop("CMP",    [bs("01000001"), reg, imm16])     # 65
addop("CMP",    [bs("01000010"), reg, imm32])     # 66
# addop("STRCMP", [bs("01000011"), reg])            # 67
# addop("ISPTR",  [bs("01000100"), reg])            # 68
# addop("ISIMM",  [bs("01000101"), reg])            # 69
addop("MOV",    [bs("01010001"), reg, reg])       # 81  # REG TO REG OR MEM TO REG
addop("MOV",    [bs("01100000"), reg, reg])       # 96  # REG TO REG
addop("MOV",    [bs("01100001"), reg, reg_deref])       # 97  # MEMORY
# addop("REP STOSD", [bs("01100010"), reg, reg, reg])  # 98
# addop("PUSH",   [bs("01110000"), reg])            # 112
# addop("POP",    [bs("01110001"), reg])            # 113
addop("RET",    [bs("01110010")])                 # 114
# addop("IDK2",   [bs("01110011"), imm8, imm8])     # 115
addop("NOP",    [bs("11000100")])                 # 196