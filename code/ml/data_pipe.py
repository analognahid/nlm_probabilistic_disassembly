#!/usr/bin/env python
# coding: utf-8

# In[1]:


from accelerate import Accelerator
import torch
import multiprocessing as mp
accelerator = Accelerator()
accelerator.state.num_processes = 3  # For 3 GPUs
device = accelerator.device
# device = 'cuda:0' if torch.cuda.is_available() else 'cpu'


# In[2]:


import magic, hashlib,  traceback ,ntpath, collections ,lief ,lief, builtins, os,sys, json,re, pickle ,threading
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
BATCH_SIZE = 850
VALIDATION_DISPLAY_SIZE = 10000
MAX_FILE_TO_USE = 300000
MODEL_NAME= "microsoft/MiniLM-L12-H384-uncased"# #bert-base-uncased
pkl_data_save_path = MODEL_SAVE_PATH+'training_data_pe'+str(MAX_FILE_TO_USE)+'.ignore.pkl'
TOKENIZER_SAVE_PATH = MODEL_SAVE_PATH + EXPERIMENT_NAME+"/tokenizer"+str(MAX_FILE_TO_USE)


# In[4]:


def make_train_test_split(bin_path):
    bin_files = [ f for f in os.listdir(bin_path) ][0:MAX_FILE_TO_USE] #if f.endswith(".exe")
    temp_dict = {key: sum(ord(c) for c in key) % 10 for key in bin_files}
    # temp_dict = dict(sorted(temp_dict.items(), key=lambda item: item[1]))
    dict_train = {k: v for k, v in temp_dict.items() if 0 <= v <= 7}
    dict_test = {k: v for k, v in temp_dict.items() if 8 <= v <= 9}
    print(len(list(dict_train.items())) ,len(list(dict_test.items())) )
    return list(dict_train.keys()) , list(dict_test.keys())
train_bins , test_bins = make_train_test_split(bin_path)



# In[5]:


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



# In[6]:


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
    


# In[7]:


import random

def limit_duplicates(sequence_list, label_list, max_duplicates):
    
    # Dictionary to store sequences and their corresponding labels
    data_dict = defaultdict(list)
    
    # Group sequences with their labels
    for seq, label in zip(sequence_list, label_list):
        data_dict[seq].append(label)


    # Prepare cleaned lists
    cleaned_sequences = []
    cleaned_labels = []
    
    for seq, labels in data_dict.items():
        # Always keep at least one occurrence
        cleaned_sequences.append(seq)
        cleaned_labels.append(labels[0])


        # If duplicates exist, randomly select up to max_duplicates
        extra_count = builtins.min( (len(labels) - 1), max_duplicates)
        selected_labels = random.sample(labels[1:], extra_count) if len(labels) > 1 else []

        # Append the selected duplicates
        cleaned_sequences.extend([seq] * len(selected_labels))
        cleaned_labels.extend(selected_labels)

    return cleaned_sequences, cleaned_labels


def process_bin_file(bin_file_path):
    SEQUENCES = []
    LABELS = []
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    offset_inst = {}
    
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
            
            ground_truth_offsets = get_ground_truth_ghidra(bin_file_path, text_section_offset, len(textSection))
    except Exception as e:
        # print("An error occurred:", e, bin_file_path)
        return [], []
    
    for byte_index in range(len(textSection)):
        try:
            instruction = next(md.disasm(textSection[byte_index: byte_index+15], text_section_offset + byte_index), None)
            offset_inst[text_section_offset + byte_index] = instruction
        except Exception as e:
            print(traceback.print_exc())
            print(e)
    
    offset_inst_dict = collections.OrderedDict(sorted(offset_inst.items()))
    DATA_OFFSETS = find_data_in_textsection(ground_truth_offsets, text_section_offset, len(textSection), offset_inst)
    
    for byte_offset in range(text_section_offset, text_section_offset + len(textSection)):
        return_value = linear_sweep(offset_inst_dict, byte_offset)
        if return_value is None:
            continue
        inst_seq, inst_addresses = return_value
        
        disassembly_decimal = replace_hex_with_decimal(inst_seq)
        numbers = sorted(set(int(s) for s in re.findall(r'\b\d+\b', disassembly_decimal)), reverse=True)
        number_word_dict = {n: len(numbers) - 1 - ix for ix, n in enumerate(numbers)}
        disassembly_num_to_words = replace_num_with_word(disassembly_decimal, number_word_dict)
        
        # SEQUENCES.append(f"{os.path.basename(bin_file_path)}_{byte_offset}_{disassembly_num_to_words}")

        if byte_offset not in ground_truth_offsets:
            if random.random() < 0.321:
                SEQUENCES.append(disassembly_num_to_words)
                LABELS.append(float(0))
        else:
            SEQUENCES.append(disassembly_num_to_words)
            LABELS.append(float(1))

    SEQUENCES, LABELS = limit_duplicates(SEQUENCES, LABELS ,2)
    return SEQUENCES, LABELS

def create_samples(bin_file_paths):
    with mp.Pool(processes=140) as pool:
        results = pool.map_async(process_bin_file, bin_file_paths)
        pool.close()
        pool.join()

    results = results.get()  
    SEQUENCES = [seq for result in results for seq in result[0]]
    LABELS = [label for result in results for label in result[1]]

    SEQUENCES ,LABELS =  limit_duplicates(SEQUENCES ,LABELS ,200 )
    
    data = pd.DataFrame({"text": SEQUENCES, "label": LABELS})
    zeros = data[data["label"] == 0].sample(frac=1, random_state=42)
    ones = data[data["label"] == 1]
    balanced_data = pd.concat([zeros, ones]).sample(frac=.321, random_state=42)
    
    SEQUENCES = balanced_data["text"].tolist()
    LABELS = balanced_data["label"].tolist()

    return SEQUENCES, LABELS

train_bin_paths       = [ os.path.join(os.path.join(bin_path, f),f+'.exe' )  for f in train_bins]
validation_bin_paths  = [ os.path.join(os.path.join(bin_path, f),f+'.exe' )  for f in test_bins ]
train_sequences, train_labels = create_samples(train_bin_paths)
print(len(train_sequences), len(train_labels) , train_labels.count(0), train_labels.count(1))
validation_sequences, validation_labels  = create_samples(validation_bin_paths)
print(len(validation_sequences), len(validation_labels) )
with open(pkl_data_save_path , 'wb') as f:
    pickle.dump([train_sequences,train_labels,validation_sequences, validation_labels], f)


# In[8]:


with open(pkl_data_save_path, "rb") as f:
    train_sequences,train_labels,validation_sequences, validation_labels = pickle.load(f)


# In[9]:


import sys,os

from transformers import BertTokenizer,BertForSequenceClassification

# If using a character-level tokenizer for sequences like DNA/Protein:


# tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_SAVE_PATH)#BertTokenizer.from_pretrained('bert-base-uncased')

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
tokenizer = tokenizer.train_new_from_iterator(train_sequences, VOCAB_SIZE)
tokenizer.save_pretrained(TOKENIZER_SAVE_PATH)

# model = BertForSequenceClassification.from_pretrained(
#     'bert-base-uncased',
#     num_labels=1  
# )

model = BertForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=1  
)

model.resize_token_embeddings(VOCAB_SIZE)
model.to(device)


optim = AdamW( model.parameters() , lr=1e-5, eps = 1e-6, betas=(0.9,0.98), weight_decay=0.01)



# In[10]:


class BinaryDataset(torch.utils.data.Dataset):
    def __init__(self, texts, labels, tokenizer):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        
    def __getitem__(self, index):
        text = self.texts[index]
        label = self.labels[index]

        # Tokenize the 
        tokenized_text = (self.tokenizer(text , max_length= MAX_TOKEN_SIZE,padding='max_length', truncation=True , return_tensors='pt')).to(device)
        
        return tokenized_text, label
        
    def __len__(self):
        return len(self.texts)


# In[11]:


# dataset = BinaryDataset(SEQUENCES, LABELS,tokenizer)
# train_size = int(0.8 * len(dataset))
# validation_size = len(dataset) - train_size

train_dataset  =  BinaryDataset(train_sequences, train_labels,tokenizer)#torch.utils.data.Subset(dataset, range(train_size))
validation_dataset = BinaryDataset(validation_sequences, validation_labels,tokenizer) #torch.utils.data.Subset(dataset, range(train_size , len(dataset)))


# train_dataset, validation_dataset = torch.utils.data.random_split(dataset, [train_size, validation_size] , generator=torch.Generator().manual_seed(42))


# In[12]:


len(train_dataset) , len(validation_dataset)


# In[13]:


train_loader      = torch.utils.data.DataLoader(train_dataset, batch_size=BATCH_SIZE ,shuffle=True) 
validation_loader = torch.utils.data.DataLoader(validation_dataset, batch_size=BATCH_SIZE, shuffle=False) #for presentation 


# In[14]:


model, optim, train_loader,validation_loader = accelerator.prepare(model, optim, train_loader,validation_loader)


# In[15]:


def training_loop(model ,data_loop, is_training = False):
    
    prediction_s, ground_truth_s = [], []
    losses = []

    for N,batch in enumerate(data_loop):
        # Forward pass
        if is_training == True:
            optim.zero_grad()
        
        batch_input, batch_labels = batch
        if len(batch_labels)<BATCH_SIZE:
            continue
            
        batch_input_ids= batch_input['input_ids']
        batch_attention_mask=batch_input['attention_mask']
        batch_token_type_ids =batch_input['token_type_ids']
        
        outputs = model(input_ids=batch_input_ids.squeeze(),
                        attention_mask=batch_attention_mask.squeeze(),
                        token_type_ids=batch_token_type_ids.squeeze(),
                        labels=batch_labels.float() )
        
#

        loss = outputs.loss
        losses.append(loss.item())
        
        logits = outputs.logits
        predictions = logits.squeeze()
        # print(logits ,predictions )

        prediction_s.extend(predictions.detach().cpu().numpy().flatten())
        ground_truth_s.extend(batch_labels.detach().cpu().numpy().flatten())


        if is_training == True:
            # loss.backward()
            accelerator.backward(loss)
            optim.step()
        # print relevant info to progress bar
        data_loop.set_description(f'Epoch {ecpoch}')
        data_loop.set_postfix(loss=loss.item())

    # Evaluation Metrics
    mse = mean_squared_error(ground_truth_s, prediction_s)
    rmse = sqrt(mse)
    mae = mean_absolute_error(ground_truth_s, prediction_s)
    r2 = r2_score(ground_truth_s, prediction_s)
    

    metrices = {'MSE':mse ,
                      'RMSE':rmse, 
                      'MAE':mae, 
                      'R²':r2,
                      'loss': (sum(losses) / len(losses))}
    return metrices , prediction_s, ground_truth_s


# In[16]:


EPOCHS = 100


global_metrices = []
v_global_metrices = []


for ecpoch in range(EPOCHS):
    
    train_loop = tqdm(train_loader, leave=True)
    model.train()
    metrices,prediction_s, ground_truth_s  = training_loop(model ,train_loop, is_training = True)
    global_metrices.append(metrices)
    print("Training metrices ",metrices)
     
    with torch.no_grad():
        model.eval()
        validation_loop = tqdm(validation_loader, leave=True)
        v_metrices, v_prediction_s, v_ground_truth_s  = training_loop(model ,validation_loop, is_training = False)


        demo_len =10000
        for i in range(minimum(demo_len , len(v_prediction_s) )):

            print('\n')
            sequence_text = validation_sequences[ i ]
            print( v_prediction_s[i], v_ground_truth_s[i] , '\n' , sequence_text)


           
        print( 'v_metrices: ',v_metrices )
        v_global_metrices.append(v_metrices)
        
    if accelerator.is_main_process:
        unwrapped_model = accelerator.unwrap_model(model)
        unwrapped_model.save_pretrained(MODEL_SAVE_PATH + EXPERIMENT_NAME)

        print('SAVING MODEL @ ',MODEL_SAVE_PATH +EXPERIMENT_NAME)
        unwrapped_model.save_pretrained(MODEL_SAVE_PATH +EXPERIMENT_NAME)
        print('saved')




# In[ ]:


#jupyter nbconvert --to script data_pipe.ipynb
# accelerate launch data_pipe.py > log.txt


# In[ ]:





# In[ ]:




