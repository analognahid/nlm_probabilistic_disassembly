from __future__ import print_function

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app


import json , collections
from collections import OrderedDict

from ghidra.program.model.data import Pointer, StructureDataType
import re

import hashlib
# from ghidra.program.model.listing import OperandType
from ghidra.program.model.lang import OperandType




def run():


    output_path = str(getScriptArgs()[0])
    # start_file_offset = 0  
    # ghidra_app.currentProgram.setImageBase(ghidra_app.getCurrentProgram().getAddressFactory().getDefaultAddressSpace().getAddress(start_file_offset), True)
    baseAddress = ghidra_app.currentProgram.getImageBase()


    all_instructions = ghidra_app.currentProgram.getListing().getInstructions(True)
    # self.print(f"\nRESULTM: [\"{self.base_address}\"]\n\n")
    addr_inst_dict =  OrderedDict()
    for instruction in all_instructions:

        address = int(instruction.getAddress().subtract(0).toString(),16) #int( inst.getAddress().subtract(0).toString(),16)

        mnemonic = instruction.getMnemonicString()
        operands = []
        for i in range(instruction.getNumOperands()):
            operands.append(instruction.getDefaultOperandRepresentation(i))

        mnemonic_with_operands = mnemonic + ' ' + ', '.join(operands)

        # print(address , mnemonic_with_operands)
        inst_file_offset = ghidra_app.currentProgram.getMemory().getAddressSourceInfo(instruction.getAddress()).getFileOffset()
        # if int(inst_file_offset)!=int(address):
        #     print(int(inst_file_offset) , int(address))
        #     print('Offset error ',  ghidra_app.currentProgram.getImageBase())
        #     # return
        # else:
        #     print(inst_file_offset ,address)
        addr_inst_dict[int(inst_file_offset)] = mnemonic_with_operands


    # sorted_keys = sorted(addr_inst_dict.keys())
    # # Reconstruct the dictionary with sorted keys
    # sorted_dict = {key: addr_inst_dict[key] for key in sorted_keys}

    with open(output_path, 'w') as fw:
        json.dump(addr_inst_dict, fw, indent=2)

# To use this script in Ghidra, save it as a .py file and run it within Ghidra's script manager.



# Starts execution here
if __name__ == '__main__':
    run()
    