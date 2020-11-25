from miasm.core.asmblock import disasmEngine
from miasm.arch.pinky.arch import mn_pinky


class dis_pinky(disasmEngine):
  """MeP miasm disassembly engine - Big Endian
      Notes:
          - its is mandatory to call the miasm Machine
  """
  def __init__(self, bs=None, **kwargs):
    super(dis_pinky, self).__init__(mn_pinky, None, bs, **kwargs)