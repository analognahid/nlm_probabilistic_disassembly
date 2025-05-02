#!/usr/bin/env python
# coding: utf-8

# In[1]:


import torch
device = 'cuda:1' if torch.cuda.is_available() else 'cpu'


# In[2]:


import magic, hashlib,  traceback ,ntpath, collections ,lief ,lief, builtins, os,sys, json,re, pickle ,random
from transformers import BertTokenizer,BertForSequenceClassification
from capstone import *
from capstone.x86 import *
import torch.nn as nn

from collections import defaultdict
from elftools.elf.elffile import ELFFile
from transformers import AdamW,AutoTokenizer
from tqdm import tqdm  # for our progress bar
from sklearn.metrics import precision_recall_fscore_support , accuracy_score,f1_score, confusion_matrix,mean_squared_error, mean_absolute_error, r2_score
from numpy import *
from num2words import num2words
import pandas as pd
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


# In[3]:


BIN_FILE_TYPE = 'PE' #or ELF
bin_path = '/home/raisul/DATA/x86_pe_msvc_O2_static/' #/home/raisul/DATA/temp/x86_pe_msvc_O2_static/'
bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) if f.endswith(".exe")]#[:2]
ground_truth_path ='/home/raisul/ANALYSED_DATA/ghidra_x86_pe_msvc_O2_static/'#'/home/raisul/DATA/temp/ghidra_x86_pe_msvc_O2_debug/'  
MODEL_SAVE_PATH= '/home/raisul/probabilistic_disassembly/models/'
EXPERIMENT_NAME = 'prototype_pe_small'

MAX_TOKEN_SIZE = 120
MAX_SEQUENCE_LENGTH = 10
VOCAB_SIZE = 500
BATCH_SIZE = 850*17
VALIDATION_DISPLAY_SIZE = 10000
MAX_FILE_TO_USE = 300000
MODEL_NAME= "microsoft/MiniLM-L12-H384-uncased"# #bert-base-uncased
pkl_data_save_path = MODEL_SAVE_PATH+'training_data_pe'+str(MAX_FILE_TO_USE)+'.ignore.pkl'
TOKENIZER_SAVE_PATH = MODEL_SAVE_PATH + EXPERIMENT_NAME+"/tokenizer"+str(MAX_FILE_TO_USE)



def replace_num_with_word(input_string , replace_dict):
    def num_to_word(match):
        number = int( match.group(0))
        return num2words(replace_dict[number]).replace(' ','').replace('-',"")
    result_string = re.sub(r'\b\d+\b', num_to_word, input_string)
    return result_string



def replace_hex_with_decimal(input_string):
    # Regular expression to find hexadecimal numbers prefixed with "0x" or "0X"
    hex_pattern = r'0[xX][0-9a-fA-F]+'
    
    # Function to convert each found hex number to decimal
    def hex_to_decimal(match):
        hex_value = match.group(0)  # Extract the matched hex number
        decimal_value = str(int(hex_value, 16))  # Convert hex to decimal
        return decimal_value
    # Substitute all hex numbers in the string with their decimal equivalents
    result_string = re.sub(hex_pattern, hex_to_decimal, input_string)
    return result_string



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
    



def process_bin_file(offset_inst_dict):
    SEQUENCES = []
    OFFSETS = []

    
    for byte_offset in offset_inst_dict:
        return_value = linear_sweep(offset_inst_dict, byte_offset)
        if return_value is None:
            continue
        inst_seq, inst_addresses = return_value
        # print(inst_addresses)
        if len(inst_addresses)<2:
            continue
        disassembly_decimal = replace_hex_with_decimal(inst_seq)
        numbers = sorted(set(int(s) for s in re.findall(r'\b\d+\b', disassembly_decimal)), reverse=True)
        number_word_dict = {n: len(numbers) - 1 - ix for ix, n in enumerate(numbers)}
        disassembly_num_to_words = replace_num_with_word(disassembly_decimal, number_word_dict)
        SEQUENCES.append(disassembly_num_to_words)
        OFFSETS.append(byte_offset)

    return SEQUENCES, OFFSETS






class BinaryDataset(torch.utils.data.Dataset):
    def __init__(self, texts,  tokenizer):
        self.texts = texts
        self.tokenizer = tokenizer
        
    def __getitem__(self, index):
        text = self.texts[index]
        
        # Tokenize the 
        tokenized_text = (self.tokenizer(text , max_length= MAX_TOKEN_SIZE,padding='max_length', truncation=True , return_tensors='pt')).to(device)
        
        return tokenized_text
        
    def __len__(self):
        return len(self.texts)




def training_loop(model ,data_loop, is_training = False):
    
    prediction_s, ground_truth_s = [], []
    losses = []

    for N,batch in enumerate(data_loop):
        # Forward pass
        if is_training == True:
            optim.zero_grad()
        
        batch_input = batch

        batch_input_ids= batch_input['input_ids']
        batch_attention_mask=batch_input['attention_mask']
        batch_token_type_ids =batch_input['token_type_ids']
        
        outputs = model(input_ids=batch_input_ids.squeeze(),
                        attention_mask=batch_attention_mask.squeeze(),
                        token_type_ids=batch_token_type_ids.squeeze())
        
        
        logits = outputs.logits
        predictions = logits.squeeze()
        # print(logits ,predictions )

        prediction_s.extend(predictions.detach().cpu().numpy().flatten())




    return   prediction_s








