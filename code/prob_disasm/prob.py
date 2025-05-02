#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os,sys, json,re, pickle
import magic, hashlib,  traceback ,ntpath, collections ,lief
from capstone import *
from capstone.x86 import *
import torch.nn as nn
import lief
from elftools.elf.elffile import ELFFile
from transformers import AdamW,AutoTokenizer
from tqdm import tqdm  # for our progress bar
from sklearn.metrics import precision_recall_fscore_support , accuracy_score,f1_score, confusion_matrix,mean_squared_error, mean_absolute_error, r2_score
from numpy import *
from num2words import num2words
import pandas as pd
from collections import defaultdict


# In[2]:


MAX_ITERATIONS = 1000  # Prevent infinite looping
NEAR_JUMP = 0.00001525902  # (2^32 - 1)^-1
REL_JUMP = 0.00392156862  # (2^16 - 1)^-1
JUST_JUMP = 0.00390625 #todo fix prob
DEF_USE = 1/16
BOTTOM = None

CONTROL_GROUPS = {
    CS_GRP_JUMP,
    CS_GRP_CALL,
    CS_GRP_RET,
    CS_GRP_IRET,
}
BRANCH_GROUPS = {
    CS_GRP_CALL,       # Function call instruction
    CS_GRP_JUMP       # Conditional and unconditional branches
}


# In[3]:


# BIN_FILE_TYPE = 'PE' #or ELF
# bin_path = '/home/raisul/DATA/x86_pe_msvc_O2_static/'#'/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
# # bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) if f.endswith(".exe")]
# bin_files = [os.path.join(bin_path, f+'/'+f+'.exe') for f in os.listdir(bin_path)]
# ground_truth_path ='/home/raisul/ANALYSED_DATA/ghidra_x86_pe_msvc_O2_static' #'/home/raisul/DATA/temp/ghidra_x86_pe_msvc_O2_debug/'  
# save_path = '/home/raisul/ANALYSED_DATA/prob_disasm_pe/'

BIN_FILE_TYPE = 'ELF'
bin_path = '/home/raisul/DATA/x86_O2_d4/' #/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
bin_files = [f for f in os.listdir(bin_path) ]
ground_truth_path ='/home/raisul/ANALYSED_DATA/ghidra_x86_O2_d4/'  
save_path = '/home/raisul/ANALYSED_DATA/prob_disasm_elf/'


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



def find_data_in_textsection(ground_truth_offsets , text_section_offset , text_section_len, offset_inst_dict):
    data_offsets = []
    for i in range(1, len(ground_truth_offsets)-1):
        distance = ground_truth_offsets[i+1] - ground_truth_offsets[i]

        inst_len = offset_inst_dict[ground_truth_offsets[i]].size 
        
        if distance!=inst_len:
            # print('offset_ranges[i]: ',ground_truth_offsets[i] , 'offset_ranges[i-1]: ',ground_truth_offsets[i-1], ' inst_len: ',inst_len  )
            # print(ground_truth_offsets[i],' ' ,hex(ground_truth_offsets[i]) , offset_inst_dict[ground_truth_offsets[i]], ' len',offset_inst_dict[ground_truth_offsets[i]].size )
            # print("\nByte GAP ###### ",distance ,' Missing bytes: ', distance - inst_len)
            
            for j in range( ground_truth_offsets[i] +inst_len , ground_truth_offsets[i+1]  ):
                data_offsets.append(j)
                # if offset_inst_dict[j]:
                #     print("# ",j, offset_inst_dict[j].mnemonic, offset_inst_dict[j].op_str , 'inst len:',offset_inst_dict[j].size )
                # else:
                #     print("# ",j, " invalid ")
            # print('\n')
        else:
            # print(ground_truth_offsets[i],' ', hex(ground_truth_offsets[i]) , offset_inst_dict[ground_truth_offsets[i]].mnemonic,offset_inst_dict[ground_truth_offsets[i]].op_str ,' len',offset_inst_dict[ground_truth_offsets[i]].size)
            pass
    return data_offsets
    

def linear_sweep(offset_inst , target_offset):
    inst_sequence = ''
    address_list = []
    
    current_offset = target_offset
    for q in range(MAX_SEQUENCE_LENGTH):

        if current_offset in offset_inst: #if end of text section
            current_instruction = offset_inst[current_offset]
            if current_instruction is None:
                return  None
                
            current_offset = current_offset + current_instruction.size
            inst_sequence+= str( hex(current_instruction.address)) +" "+ current_instruction.mnemonic +' '+ current_instruction.op_str+ ' ; ' 
            address_list.append(current_instruction.address)
            
            if current_instruction.mnemonic in ["ret", "jmp"]: #break linear sweep
                break
                

    return inst_sequence, address_list
    


# In[5]:


def _compute_destinations(disasm):
    """ Compute successor addresses (CFG) and ensure function epilogues are correctly identified. """
    dests, preds = {}, defaultdict(list)
    last_offset = list(disasm.keys())[-1]
    first_offset = list(disasm.keys())[0]

    for offset, details in disasm.items():
        if details==None:
            continue
        inst_str = details.mnemonic +' ' + details.op_str
        next_offset = offset + details.size



        if not set(details.groups) & CONTROL_GROUPS:
            # Default fallthrough for non-control flow instructions
            if next_offset <= last_offset:
                dests[offset] = [next_offset]
                # preds[next_offset].append(offset)
            else:
                dests[offset] = []
        else: #control instruction
            #unconditional jump
            if details.id == X86_INS_JMP and details.operands and details.operands[0].type == CS_OP_IMM:
                 # Unconditional jump
                op_value = details.operands[0].imm
                if op_value>=first_offset and op_value<=last_offset:
                    dests[offset] = [op_value]
                    # preds[op_value].append(offset)
            
            # elif "COND_BR" in details.groups or "CALL" in details.groups:
            elif (CS_GRP_JUMP in details.groups or CS_GRP_CALL in details.groups) :
                if details.operands and details.operands[0].type == CS_OP_IMM:
                    jump_target = details.operands[0].imm
    
                    if next_offset<=last_offset:
                        dests[offset] = [next_offset]
                        # preds[next_offset].append(offset)
                                     
                    if jump_target>=first_offset and jump_target<=last_offset and jump_target!=next_offset:
                        if offset in dests:
                            dests[offset].append(jump_target)
                        else:
                            dests[offset] = [jump_target]
        
            else:
                # print('>>>>>  ',offset, ' : ' ,inst_str)
                dests[offset] = None

        if offset in dests:
            if dests[offset] is not None:
                for target in dests[offset]:
                    preds[target].append(offset)

    return dests, preds




            


# In[6]:


def _compute_occlusion(disasm):
    """ Identify overlapping instructions and remove """
    occlusion = defaultdict(list)
    valid_instructions = set()

    for offset, details in disasm.items():
        if details!= None:
            for i in range(offset + 1, offset + details.size):
                occlusion[i].append(offset)

    # fix nahid
    covered = set()
    for offset in sorted(disasm.keys()):
        if disasm[offset] is None:
            continue
        if offset in covered:
            # print(f"Skipping {offset} due to occlusion")
            continue  # Skip if another instruction already claimed this byte

        valid_instructions.add(offset)
        for i in range(offset, offset + disasm[offset].size):
            covered.add(i)  # Mark all bytes of this instruction as covered

    # print(f"Final valid instructions after occlusion: {sorted(valid_instructions)}")
    return occlusion, valid_instructions





# In[7]:


def get_recursive_descent_cfg(disasm,ALL_RD_CFG):
    debug = False
    # global ALL_RD_CFG, cfg

    for offset in disasm:
        if debug:
            print('\n-------------------------------------------------------\n')
        RD_CFG = []
        current = offset
        while True:

            # print('current: ',current)

            #prevent cycle
            if current in RD_CFG:
                break
            #out of bound
            if current not in disasm:
                break
            #current invalid
            if disasm[current] is None:
                break


            #return
            if disasm[current].mnemonic in ["ret"]:
                break
            

            if disasm[current].mnemonic == 'jmp':
                if disasm[current].operands[0].type == CS_OP_IMM:
                    next =  disasm[current].operands[0].imm
                else:
                    #todo fix indirect
                    if debug:
                        print(offset, disasm[offset])
                    break
            else :
                next =  current + disasm[current].size 


            if next not in disasm:
                break
            RD_CFG.append(next)
            current = next 
            
        #save         
        ALL_RD_CFG [offset] = RD_CFG










# In[8]:


def get_recursive_preds(disasm ,ALL_RD_PRED ,ALL_RD_CFG):

    #todo fix nahid
    for offset in disasm:
        ALL_RD_PRED[offset] = []

    for offset in disasm:
        for target in ALL_RD_CFG[offset] :
            if target in disasm: #last byte
                if target not in ALL_RD_PRED[target] :
                    ALL_RD_PRED[target].append(offset)




# In[ ]:





# In[ ]:





# In[9]:


def initialize(disasm,data_prob,H_list):
    for offset in range(list(disasm.keys())[0], list(disasm.keys())[-1]  + 1):
    
            if disasm[offset] is  None:
                data_prob[offset] =  1.0
            # elif offset in valid_instructions:
            #     data_prob[offset] =  0.9
            else:
                data_prob[offset] = BOTTOM
    
            H_list[offset] = []



# In[10]:


def _hint_one(offset, disasm, preds, H_list):

    """ Implements Control Flow Convergence hint. """
    debug = False

    if offset not in preds:
        return

    branches = [prev for prev in preds[offset] if set(disasm[prev].groups) & BRANCH_GROUPS]

    if disasm[offset]:
        if debug:
            print( '#  ' if offset in ground_truth_offsets else '   ', \
                  ' $ ' if len(set(disasm[offset].groups) & BRANCH_GROUPS) else '   ', \
                  ' ',offset , ' : ', hex(offset),' ',disasm[offset].mnemonic +' ' + disasm[offset].op_str  , ' ' , disasm[offset].size)

    if len(branches)<2:
        return

    if debug:
        print(branches)
    for branch in branches:
        # H[branch].add(("1rel" if disasm[branch].size == 2 else "1near", offset))

        jump_len = disasm[branch].operands[0].imm - (disasm[branch].address + disasm[branch].size)
        
        if -128 <= jump_len <= 127:
            H_list[branch].append( REL_JUMP )
            H_list[offset].append( REL_JUMP) 
        else:
            H_list[branch].append( NEAR_JUMP)
            H_list[offset].append( NEAR_JUMP )
        if debug:
            print('$$$ len', jump_len)
        

def _hint_one_one(offset, disasm, cfg, H_list):

    """ Implements valid jump. """
    debug = False



    if set(disasm[offset].groups) & BRANCH_GROUPS:
        next_offset_by_size = offset + disasm[offset].size
        if offset in cfg:
            if any(element != next_offset_by_size for element in cfg[offset]):
                H_list[offset].append( JUST_JUMP )

        

def _hint_two(offset, disasm,preds,H_list):

    """ Implements Control Flow Crossing hint. """
    debug = False
    
    if debug:
        # print( '#' if offset in ground_truth_offsets else ' ',' ',offset , ' : ', hex(offset),' ',disasm[offset].mnemonic +' ' + disasm[offset].op_str  , ' ' , disasm[offset].size)
        print( '#  ' if offset in ground_truth_offsets else '   ', \
              ' $ ' if len(set(disasm[offset].groups) & BRANCH_GROUPS) else '   ', \
              ' ',offset , ' : ', hex(offset),' ',disasm[offset].mnemonic +' ' + disasm[offset].op_str  , ' ' , disasm[offset].size)
    inst2_offset = offset
    if not CS_GRP_JUMP in disasm[inst2_offset].groups: #inst2 have to be a control one
        return
    
    
    inst2_size   = disasm[inst2_offset].size
    inst3_offset =  inst2_offset + inst2_size

    if inst3_offset not in preds: #inst 3 has to be a target of inst1
        return

    inst3_preds_list = preds[inst3_offset]

    if inst2_offset in inst3_preds_list:
        inst3_preds_list.remove(inst2_offset)

    for inst1_offset in inst3_preds_list:
        if CS_GRP_JUMP in disasm[inst1_offset].groups: #ins1 has to be a control flow instruction

            inst1_jump_len = disasm[inst1_offset].operands[0].imm - (disasm[inst1_offset].address + disasm[inst1_offset].size)
            inst2_jump_len = disasm[inst2_offset].operands[0].imm - (disasm[inst2_offset].address + disasm[inst2_offset].size)

            

            if -128 <= inst1_jump_len <= 127:  
                hint_type_inst1 = NEAR_JUMP
            else:
                hint_type_inst1 = REL_JUMP

            if -128 <= inst2_jump_len <= 127:  
                hint_type_inst2 = NEAR_JUMP
            else:
                hint_type_inst2 = REL_JUMP

            H_list[inst1_offset].append( hint_type_inst1 )
            H_list[inst3_offset].append( hint_type_inst1 )
            H_list[inst2_offset].append( hint_type_inst2 )


            if debug:
                print('inst1: ', inst1_offset , 'inst2: ',inst2_offset, 'inst3: ',inst3_offset)
                for o in [inst1_offset , inst2_offset, inst3_offset]:
                    if o not in ground_truth_offsets:
                            print('# # # '*10 ,o)
        
        




def _hint_three(offset, disasm, preds,H_list):

    """ Implements Register Define-Use Relation hint. """

    debug = False
    # if offset not in ground_truth_offsets:
    #     return

    
    if debug:
        print('\n\n')
        print( '#' if offset in ground_truth_offsets else ' ',' ',offset , ' : ', hex(offset),' ',disasm[offset].mnemonic +' ' + disasm[offset].op_str  , ' ' , disasm[offset].size)

        regs_read, regs_write = disasm[offset].regs_access()
        current_reads = set(disasm[offset].reg_name(r) for r in regs_read)
        current_writes = set(disasm[offset].reg_name(r) for r in regs_write)
        
        print('read'    , current_reads   )
        print('writes'  , current_writes  )
        
        # print('           current read: ',disasm[offset].regs_read , \
        #       [disasm[offset].reg_name(r) for r in disasm[offset].regs_read ] ,  \
        #       [md.reg_name(r) for r in disasm[offset].regs_read ]) #if md.reg_name(r) not in ('eflags', 'rflags')]
        # print('           current WRITE: ',  [disasm[offset].reg_name(r) for r in disasm[offset].regs_write] ) #if md.reg_name(r) not in ('eflags', 'rflags')]

    
    
    
    if offset not in preds:
        return


    regs_read, regs_write = disasm[offset].regs_access()
    curr_reg_read = set(disasm[offset].reg_name(r) for r in regs_read if disasm[offset].reg_name(r) not in ('eflags', 'rflags'))


    # curr_reg_read = set( [ disasm[offset].reg_name(r) for r in disasm[offset].regs_read if disasm[offset].reg_name(r) not in ('eflags', 'rflags')])
    if debug:
        print( '           curr: red: ' , curr_reg_read)
    for prev in preds[offset]:

        _ , prev_regs_write = disasm[prev].regs_access()
        prev_reg_write = set(disasm[prev].reg_name(r) for r in prev_regs_write if disasm[prev].reg_name(r) not in ('eflags', 'rflags'))
        
        if debug:
            print('           prev: write: ',prev, prev_reg_write ) # if disasm[offset].reg_name(r) not in ('eflags', 'rflags')])
        
        if prev_reg_write & curr_reg_read:
            H_list[prev].append(DEF_USE)
            H_list[offset].append(DEF_USE)
            
            if debug:
                print("           ----> ", prev)




    


# In[11]:


def update_H(H_list, H):
    """ MATH determined from https://www.cs.purdue.edu/homes/zhan3299/res/ICSE19.pdf
    """

    for offset in H_list:
        
        prod = 1.0
        if len(H_list[offset])>0:
            for hint in H_list[offset]:
                prod = prod * hint
            H[offset] = prod
        else:
            H[offset] = BOTTOM




# In[12]:


import math
def safe_product(numbers):
    res = None
    if len(numbers)==1:
        res =  numbers[0]
    else:
        log_sum = sum(math.log(x) for x in numbers)
        res = math.exp(log_sum)
    if res == 0:
        return 2.2250738585072014e-307
    return res
    

def calc_data_prob(offset ,RH ,H):
     
    d=1.0
    factors = []
    for rh in RH[offset]:
        factors.append(H[rh])
    if len(factors):
        d = safe_product(factors)
    return d


def _forward_propagation(disasm, data_prob, cfg, H , RH,ALL_RD_CFG):
    """ Iterative analyais to find instructions that lead to bad assembly.
        Outside of control flow, this is guarenteed to be data

        attempting to write ~line 10 algorithm 1 of https://www.cs.purdue.edu/homes/zhan3299/res/ICSE19.pdf
    """

    debug = False
    fixed_point = True
    for offset, inst in disasm.items():
        if data_prob[offset] == 1.0:
            # Already know instruction is data
            continue
        if disasm[offset] is None:
            continue

        # line 13-15
        # update this instructions probability
        if H[offset] and offset not in RH[offset]:
            RH[offset].add(offset)
            
            # data_prob[offset] = 1.0
            data_prob[offset] = calc_data_prob(offset, RH ,H)
            # for h in RH[offset]:
            #     data_prob[offset] *= H[h]
                
            if 0 in data_prob.values():
                return
        #line 16-20
        for n in ALL_RD_CFG[offset]:
            diff = set(RH[offset]) - set(RH[n])
            if len(diff):
                RH[n] = RH[n] | diff
                data_prob[n] = calc_data_prob(n, RH ,H)
                
                if n<offset:
                    fixed_point = False
    return fixed_point



# In[ ]:





# In[13]:


import builtins
def _adjust_occlusion_probs(disasm, data_prob, occlusion_space):
    """ attempting to write ~line 22 algorithm 1 of https://www.cs.purdue.edu/homes/zhan3299/res/ICSE19.pdf

        Struggled with which probabilities should be adjusted and whether that is a global change
        or incremental


    """
    for offset, detail in disasm.items():
        if not data_prob[offset] == BOTTOM:
            # Only update if data probability is unknown
            continue

        
        # Find probability of being data for each overlapping instruction
        occluded_probs = []
        for j in occlusion_space[offset]:
            if data_prob[j] == BOTTOM : #todo nahid hack to prevent zero data prob
                continue
            occluded_probs.append(data_prob[j])

        if len(occluded_probs)==0:
            # If not overlapping instructions, leave probability as is
            continue

        # Step II. In lines 22-24, the algorithm traverses all the addresses
        # and performs local propagation of probabilities within occlusion space of individual instructions. Particularly, for each
        # address i, it finds its occluded peer j that has the minimal
        # probability (i.e., the most likely instruction). The likelihood
        # of i being data is hence computed as 1 − D[j] (line 24).
        new_occluded_prob = 1 - builtins.min(occluded_probs) # nahid fix*0.9
        # print(data_prob[offset] , new_occluded_prob)
        if new_occluded_prob==0:
            data_prob[offset] = 0.1  #TODO nahid fix todo#2.2250738585072014e-307

        else:
            data_prob[offset] = new_occluded_prob 
        



# In[ ]:





# In[14]:


def _back_propagation(disasm, data_prob ,ALL_RD_PRED):
    """ Iterative analysis to find instructions that lead to bad assembly.
        Outside of control flow, this is guaranteed to be data.

        Attempting to implement ~line 25 of Algorithm 1 from:
        https://www.cs.purdue.edu/homes/zhan3299/res/ICSE19.pdf
    """
    debug = False
    fixed_point = True
    for offset in disasm:
        
        if data_prob[offset] == BOTTOM :#or offset not in ALL_RD_PRED
            # Cannot propagate unknown probability or unknown predecessors
            continue
       

        for p in ALL_RD_PRED[offset]:
            # Updated probability propagation logic

            if debug:
                print('here1',offset , p,data_prob[p] ,data_prob[offset])

            if data_prob[p] is BOTTOM or data_prob[p] < data_prob[offset]:
                data_prob[p] = data_prob[offset] 
                fixed_point = False  # Mark that we've updated a probability

                if debug:
                    print('main', offset ,  'backtracked', p)
                if p > offset:
                    # Ensure continued processing if new updates occur
                    fixed_point = False


    return fixed_point

# _back_propagation(disasm)


# In[15]:


def is_interrupt(instr):
    return instr.mnemonic in {'int', 'int3', 'syscall', 'sysenter', 'iret', 'iretq'}
def is_nop(instr):
    return instr.mnemonic == 'nop'


# In[16]:


def normalize(disasm,data_prob ,ground_truth_offsets ,occlusion_space, P):

    debug = False
        
    for offset in disasm:
        
        if disasm[offset] is None:
            P[offset] = 0
            continue
        if data_prob[offset] ==1.0 or data_prob[offset] is None:
            P[offset] = 0
            continue
    
        #padding
        if is_interrupt(disasm[offset]) or is_nop(disasm[offset]):
            P[offset] = 0
            if offset in ground_truth_offsets:
                ground_truth_offsets.remove(offset)
            continue
    
        # if offset == 3455:
        #     debug = True
        # else:
        #     debug = False
        
        s=1/data_prob[offset]
    
        if s == float('inf'):
            if debug:
                print('infinity')
            P[offset] = 1
            continue
            
        if debug:
            print('s=1/data_prob[offset]' , s,data_prob[offset])
        
        for j in occlusion_space[offset]:
            if data_prob[j]:
                s = s + 1/(data_prob[j] )
            else:
                pass #todo fix nahid hack
            if debug:
                print('s = s + 1/(data_prob[j] )', s)
        
        if debug:
            print('final',(1/data_prob[offset]) /s)
        final_res = (1/data_prob[offset]) /s
        if final_res == float('nan'):
            P[offset] = 1 
            continue
        P[offset] = final_res


    predictions = []
    for offset, p in P.items():
    
            if p >.45:
                predictions.append(offset)
            # else:
            #     print(offset, p)
    false_positive = set(predictions) -set (ground_truth_offsets)
    false_negative = set (ground_truth_offsets) - set(predictions)
    true_positive = set (ground_truth_offsets) & set(predictions)
    print('false_positive: ',len(false_positive) , ' false_negative: ',len(false_negative) , ' true_positive: ',len(true_positive), 'total:', len(ground_truth_offsets)) 

    if debug:
        for offset in disasm:
            # try:
            tok = "   "
            if offset in false_negative:
                tok = "N-N"
            elif offset in false_positive:
                tok = "x  "
            if disasm[offset]:
                print( str((P[offset] )).ljust(10),'  ',str( (data_prob[offset] ) ).ljust(10), str(H[offset]).ljust(10) ,str(RH[offset]).ljust(20) ,tok, '#' if offset in ground_truth_offsets else ' ',' ',offset , ' : ', hex(offset),' ',disasm[offset].mnemonic +' ' + disasm[offset].op_str  , ' ' , disasm[offset].size)
            else:
                print( str((P[offset])).ljust(10),'  ',str( (data_prob[offset] ) ).ljust(10), str(H[offset]).ljust(10) ,str(RH[offset]).ljust(20) , tok,'   ', offset , ' : '    , 'invalid instruction') 

        # except Exception as e:
        #     print(traceback.print_exc() )
        #     print(e)
    return len(false_positive),len(false_negative),len(true_positive),len(ground_truth_offsets)


# In[17]:


# false_positive:  112  false_negative:  21  true_positive:  1459 total: 1480
# just one one false_positive:  155  false_negative:  46  true_positive:  1434 total: 1480


# In[ ]:





# In[18]:


def linear_sweep(disasm, valid_instructions, ground_truth_offsets):

    debug = False
    _ = list(valid_instructions)
    predictions = _.copy()
    for offset in _:
        if is_interrupt(disasm[offset]) or is_nop(disasm[offset]):
            predictions.remove(offset)
    false_positive = set(predictions) -set (ground_truth_offsets)
    false_negative = set (ground_truth_offsets) - set(predictions)
    true_positive = set (ground_truth_offsets) & set(predictions)
    print('false_positive: ',len(false_positive) , ' false_negative: ',len(false_negative) , ' true_positive: ',len(true_positive), 'total:', len(ground_truth_offsets)) 
    print(predictions.count(0))

    if debug:
        for offset in disasm:
        
            # try:
                tok = "   "
                if offset in false_negative:
                    tok = "N-N"
                elif offset in false_positive:
                    tok = "x  "
                if disasm[offset]:
                    print( str((P[offset] )).ljust(20),'  ',str( (data_prob[offset] ) ).ljust(20), str(H[offset]).ljust(10) ,str(RH[offset]).ljust(20) ,tok, '#' if offset in ground_truth_offsets else ' ',' ',offset , ' : ', hex(offset),' ',disasm[offset].mnemonic +' ' + disasm[offset].op_str  , ' ' , disasm[offset].size)
                else:
                    print( str((P[offset] )).ljust(20),'  ',str( (data_prob[offset]) ).ljust(20), str(H[offset]).ljust(10) ,str(RH[offset]).ljust(20) , tok,'   ', offset , ' : '    , 'invalid instruction') 
        
            # except Exception as e:
            #     print(traceback.print_exc() )
            #     print(e)
    return len(false_positive),len(false_negative),len(true_positive),len(ground_truth_offsets)


# In[19]:


def process_binary(bin_file_path):
    if BIN_FILE_TYPE == "ELF":
        bin_file_path = os.path.join(bin_path , bin_file_path)
# for bin_file_path in bin_files[3:4]:#[1:1000]:

    file_name = os.path.basename(bin_file_path)
    json_file_path = os.path.join( save_path, file_name + ".json")
    if os.path.exists(json_file_path):
        return
        
    # if BIN_FILE_TYPE == "ELF":
    #     bin_file_path = os.path.join(bin_path , bin_file_path)
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    offset_inst = {}

    
    with open(bin_file_path, 'rb') as f:

        try:
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

        except Exception as e:
            print("An error occurred:", e ,bin_file_path)
            return

    inst_sizes = {}
    for byte_index in range(len(textSection)):
        try:    

            instruction = next(md.disasm(textSection[byte_index: byte_index+15 ], text_section_offset + byte_index ), None)
            offset_inst[text_section_offset+byte_index] = instruction
            inst_sizes [text_section_offset+byte_index] = instruction.size if instruction else None
            
            # if instruction:
            #     print("%d:\t%s\t%s _\t%x" %(int(instruction.address), instruction.mnemonic, instruction.op_str, instruction.size))
            # else:
            #     print("%d:\t%s " % (text_section_offset + byte_index  , 'invalid instruction') )


        except Exception as e:
            print(traceback.print_exc() )
            print(e)

    
    
    disasm = collections.OrderedDict(sorted(offset_inst.items()))

    DATA_OFFSETS = find_data_in_textsection(ground_truth_offsets , text_section_offset , len(textSection) , offset_inst)
    code_boundary = text_section_offset+len(textSection)
    
    ####################### prob disasm calls
    
    ALL_RD_CFG = {}
    H_list = {}
    ALL_RD_PRED ={}
    res, data_prob,  = {}, {}
    
    H={}
    RH = {}
    P = {}



    ##############################

    cfg, preds = _compute_destinations(disasm)
    cfg = dict(sorted(cfg.items()))
    preds = dict(sorted(preds.items()))
    occlusion_space, valid_instructions =_compute_occlusion(disasm)
    get_recursive_descent_cfg(disasm,ALL_RD_CFG )
    get_recursive_preds(disasm , ALL_RD_PRED ,ALL_RD_CFG)
    initialize(disasm,data_prob,H_list)
    
    for offset in disasm:
        if disasm[offset] is None:
            continue
        _hint_one_one(offset, disasm, cfg, H_list)
        _hint_one(offset, disasm, preds, H_list)
        _hint_two(offset, disasm,preds ,H_list)
        _hint_three(offset, disasm, preds,H_list)
    update_H(H_list, H)
    for offset, inst in disasm.items():
        RH[offset] = set()
    
    
    for _ in range(MAX_ITERATIONS): #MAX_ITERATIONS
        fixed_point = True
        fixed_point = _forward_propagation(disasm, data_prob, cfg, H, RH , ALL_RD_CFG) and fixed_point
        fixed_point = _adjust_occlusion_probs(disasm, data_prob, occlusion_space) and fixed_point
        fixed_point = _back_propagation(disasm ,data_prob , ALL_RD_PRED) and fixed_point
        
        if fixed_point is True:
            break
    
    prob_disasm_false_positive,prob_disasm_false_negative,prob_disasm_true_positive,prob_disasm_total = normalize(disasm,data_prob ,ground_truth_offsets ,occlusion_space , P)
    
    linear_sweep_false_positive,linear_sweep_false_negative,linear_sweep_true_positive,linear_sweep_total = linear_sweep(disasm, valid_instructions, ground_truth_offsets)
    ################## saving 
    
    
    prob_disasm_results = {
        "prob_disasm_false_positive": prob_disasm_false_positive,
        "prob_disasm_false_negative": prob_disasm_false_negative,
        "prob_disasm_true_positive": prob_disasm_true_positive,
        "prob_disasm_total": prob_disasm_total,
        "linear_sweep_false_positive": linear_sweep_false_positive,
        "linear_sweep_false_negative": linear_sweep_false_negative,
        "linear_sweep_true_positive": linear_sweep_true_positive,
        "linear_sweep_total": linear_sweep_total
        }


    
    # Save to file
    with open(json_file_path, 'w') as f:
        json.dump(prob_disasm_results, f, indent=4)


# In[ ]:


import multiprocessing
from multiprocessing import active_children

if __name__ == "__main__":  # Allows for the safe importing of the main module
    print("There are {} CPUs on this machine".format( multiprocessing.cpu_count()))
    
    number_processes = int(multiprocessing.cpu_count() *1 )
    pool = multiprocessing.Pool(number_processes)


    results = pool.map_async(process_binary, bin_files)
    pool.close()
    pool.join()

    print(" DONE ALL SUCCESSFULLY Alhamdulillah"*50)




# In[ ]:


#jupyter nbconvert --to script prob.ipynb
# accelerate launch prob.py > log.txt

