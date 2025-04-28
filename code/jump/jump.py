#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os,sys, json,re, pickle
import magic, hashlib,  traceback ,ntpath, collections ,lief
from capstone import *
from capstone.x86 import *
import torch.nn as nn
import lief,traceback
from elftools.elf.elffile import ELFFile
from transformers import AdamW,AutoTokenizer
from tqdm import tqdm  # for our progress bar
from sklearn.metrics import precision_recall_fscore_support , accuracy_score,f1_score, confusion_matrix,mean_squared_error, mean_absolute_error, r2_score
from numpy import *
from num2words import num2words
import pandas as pd


# In[2]:


# BIN_FILE_TYPE = 'PE' #or ELF
# # bin_path = '/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
# # # bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) if f.endswith(".exe")]
# # bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) if f.endswith(".exe")]
# bin_path = '/home/raisul/DATA/x86_pe_msvc_O2_static/' #/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
# bin_files = [f for f in os.listdir(bin_path) ]
# bin_files       = [ os.path.join(os.path.join(bin_path, f),f+'.exe' )  for f in bin_files]
# ground_truth_path ='/home/raisul/ANALYSED_DATA/ghidra_x86_pe_msvc_O2_static/'  

# MAX_SEQUENCE_LENGTH = 10



BIN_FILE_TYPE = 'ELF' #or ELF
# bin_path = '/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
# # bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) if f.endswith(".exe")]
# bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) if f.endswith(".exe")]
bin_path = '/home/raisul/DATA/x86_O2_d4/' #/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
bin_files = [f for f in os.listdir(bin_path) ]
# bin_files       = [ os.path.join(os.path.join(bin_path, f),f+'.exe' )  for f in bin_files]
ground_truth_path ='/home/raisul/ANALYSED_DATA/ghidra_x86_O2_d4/'  
meta_path = '/home/raisul/pun_dataset/meta/' 
save_path = "/home/raisul/ANALYSED_DATA/jump_data/"
MAX_SEQUENCE_LENGTH = 10




# In[3]:


bin_files = bin_files#[0:10000]


# In[ ]:





# In[4]:


def get_ground_truth_ghidra(exe_path, text_section_offset , text_section_len):

    text_sextion_end = text_section_offset + text_section_len
    
    elf_file_name = os.path.basename(exe_path)
    ghidra_file_path = os.path.join(ground_truth_path, elf_file_name.split('.')[0]) + '.json'
    
    with open(ghidra_file_path, "r") as file:
        ghidra_data = json.load(file)

    ground_truth_offsets = list(ghidra_data.keys())

    ground_truth_offsets = [int(i) for i in ground_truth_offsets]
    ground_truth_offsets = [x for x in ground_truth_offsets if text_section_offset <= x <= text_sextion_end]
    ground_truth_offsets.sort()
    return ground_truth_offsets

import re
def find_switch_lines(filepath):
    try:
        with open(filepath, "r" , encoding="utf-8", errors="replace") as f:   
            lines = f.readlines()

        # Remove block comments across the file
        code = ''.join(lines)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        lines = code.splitlines()

        switch_lines = []
        for idx, line in enumerate(lines, start=1):
            line_clean = re.sub(r'//.*', '', line)  # remove inline comments
            if re.search(r'\bswitch\s*\(.*?\)', line_clean):
                switch_lines.append(idx)

        return switch_lines

    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return []

def print_c_code(filepath):
    return
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return

    print(f"📄 Printing contents of: {filepath}\n" + "-"*60)

    with open(filepath, "r") as f:
        for i, line in enumerate(f, start=1):
            print(f"{i:4d}: {line.rstrip()}")



import shutil
from datetime import datetime
def copy_files_to_new_dir(src1, src2, src3, new_dir_path):
    # return
    os.makedirs(new_dir_path, exist_ok=True)
    # Copy both files into the new directory
    for src in [src1, src2,src3]:
        shutil.copy(src, new_dir_path)




def is_jump_table_candidate(insn):
    if insn.mnemonic != "jmp":
        return False
    
    if len(insn.operands) != 1:
        return False
    
    op = insn.operands[0]
    if op.type == CS_OP_MEM:
        mem = op.mem
        if mem.scale in (4, 8) and mem.index != 0:
            return 1
    if op.type == CS_OP_REG:
        # We may still need to check prior instruction patterns (e.g., LEA/MOV)
        return 2
    return False




# In[5]:


SEQUENCES = []
LABELS     = []
HISTORY_SIZE =20
for bin_file_name in bin_files:

    bin_file_path = os.path.join(bin_path , bin_file_name)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    offset_inst = {}

    ground_truth_offsets = None


    try:
        with open(bin_file_path, 'rb') as f:
        
            if BIN_FILE_TYPE == "ELF":
                elffile = ELFFile(f)
                textSection = elffile.get_section_by_name('.text').data()
                text_section_offset = elffile.get_section_by_name('.text')['sh_offset']
                
              
            elif BIN_FILE_TYPE == "PE":
    
                        
                pe_file = lief.parse(bin_file_path)
                text_section = pe_file.get_section(".text")
                text_section_offset = text_section.pointerto_raw_data
                textSection = bytes(text_section.content)
                
            ground_truth_offsets = get_ground_truth_ghidra(bin_file_path, text_section_offset , len(textSection))
            
        meta_file_path = os.path.join(meta_path , bin_file_name+'.json')

        # Open and load the JSON
        with open(meta_file_path, "r") as f:
            meta_data = json.load(f)
        src_file_path = meta_data ['x86_O2_d4']['src_path']
        #hack bad

        if 'nahid_personal' not in src_file_path:
            src_file_path = src_file_path.replace('/media/raisul/' , '/media/raisul/nahid_personal/')

        
        inst_sizes = {}
        instruction_history = []  # Circular buffer for last 20 instructions
        for byte_index in ground_truth_offsets:
     
                instruction = next(md.disasm(textSection[byte_index-text_section_offset: byte_index+15-text_section_offset ],   byte_index ), None)

                if instruction is None:
                    continue
                if len(instruction_history) >= HISTORY_SIZE:
                    instruction_history.pop(0)
                instruction_history.append(instruction)

                # if is_jump_table_candidate(instruction):
                if instruction.mnemonic=='jmp' and instruction.op_str=='rax':
                    switch_src_lines =  find_switch_lines(src_file_path) 
                    if len(switch_src_lines)>0:

                        #
                        if instruction_history[-2].group(CS_GRP_JUMP):          #instruction_history[-2].mnemonic in ['je' , 'jz']:
                            continue
                        ghidra_file_path = os.path.join(ground_truth_path, bin_file_name) + '.json'
                        copy_files_to_new_dir(src_file_path,bin_file_path ,ghidra_file_path, os.path.join(save_path , os.path.basename(src_file_path.split('.')[0])+bin_file_name ) )
                        
                        
                        
                        
                        
                        
                        print_c_code(src_file_path)                    
                        print("\n\n")
                        print(bin_file_path ,src_file_path)
                        print("\n\n")
                        
                        print(hex(byte_index) ,' : ' , instruction.mnemonic+ ' ' + instruction.op_str)
                        print("Last 20 instructions:")
                        for  hist_inst in instruction_history:
                            print(hex(hist_inst.address) , hist_inst.mnemonic, hist_inst.op_str)
                        print("\n\n\n\n\n")
                        break
            
    except Exception as e:
        traceback.print_exc()
        continue                
    
    


# In[ ]:





# In[6]:


#jupyter nbconvert --to script data_pipe.ipynb
# accelerate launch data_pipe.py > log.txt


# In[ ]:





# In[ ]:




