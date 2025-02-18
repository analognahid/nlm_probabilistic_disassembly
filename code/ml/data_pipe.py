#!/usr/bin/env python
# coding: utf-8

# In[3]:


from accelerate import Accelerator
accelerator = Accelerator()
# from accelerate import notebook_launcher

# Optionally, you can specify the number of processes like this:
accelerator.state.num_processes = 3  # For 3 GPUs

# This will automatically handle device placement for you
device = accelerator.device


import torch
# device = 'cuda:0' if torch.cuda.is_available() else 'cpu'


# In[8]:


import os,sys, json
import magic, hashlib, os, traceback
import ntpath
from capstone import *
from capstone.x86 import *
import torch.nn as nn
import collections
import traceback
import lief
from elftools.elf.elffile import ELFFile
from transformers import AdamW,AutoTokenizer
from tqdm import tqdm  # for our progress bar
from sklearn.metrics import precision_recall_fscore_support , accuracy_score,f1_score, confusion_matrix,mean_squared_error, mean_absolute_error, r2_score

from numpy import *


# In[9]:


bin_path = '/home/raisul/DATA/x86_O2_d4/' #'/home/raisul/DATA/x86_O2_d4_mingw32_PE' 

bin_files = [os.path.join(bin_path, f) for f in os.listdir(bin_path) ][0:2000]

ground_truth_path ='/home/raisul/ANALYSED_DATA/ghidra_x86_O2_d4/' # '/home/raisul/ANALYSED_DATA/ghidra_x86_O2_d4_mingw32_PE'  


# In[10]:


MAX_TOKEN_SIZE = 256
BATCH_SIZE = 260


# In[11]:


len(bin_files)


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
            


# In[7]:


def linear_sweep(offset_inst , target_offset):
    inst_sequence = ''
    max_seq_length = 15

    
    current_offset = target_offset
    for q in range(max_seq_length):

        if current_offset in offset_inst: #if end of text section
            current_instruction = offset_inst[current_offset]
            if current_instruction is None:


                return  None
                
            current_offset = current_offset + current_instruction.size
            inst_sequence+= str( hex(current_instruction.address)) +" "+ current_instruction.mnemonic +' '+ current_instruction.op_str+ ' ; ' 

            if current_instruction.mnemonic in ["ret", "jmp"]: #break linear sweep
                return inst_sequence

    return inst_sequence


SEQUENCES = []
LABELS     = []

for bin_file_path in bin_files:

    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    offset_inst = {}

    
    with open(bin_file_path, 'rb') as f:

        try:
            elffile = ELFFile(f)
           
            textSection = elffile.get_section_by_name('.text').data()
        
            text_section_offset = elffile.get_section_by_name('.text')['sh_offset']
          
            ground_truth_offsets = get_ground_truth_ghidra(bin_file_path, text_section_offset , len(textSection))
            
        except Exception as e:
            print("An error occurred:", e ,bin_file_path)
            continue

    for byte_index in range(len(textSection)):
        
    
        try:    

            instruction = next(md.disasm(textSection[byte_index: byte_index+15 ], text_section_offset + byte_index ), None)
            offset_inst[text_section_offset+byte_index] = instruction
            
            # if instruction:
            #     print("%d:\t%s\t%s _\t%x" %(int(instruction.address), instruction.mnemonic, instruction.op_str, instruction.size))
            # else:
            #     print("%d:\t%s " % (text_section_offset + byte_index  , 'invalid instruction') )
                
            

        except Exception as e:
            print(traceback.print_exc() )
            print(e)

    
    
    offset_inst_dict = collections.OrderedDict(sorted(offset_inst.items()))

    DATA_OFFSETS = find_data_in_textsection(ground_truth_offsets , text_section_offset , len(textSection) , offset_inst)


    
    for byte_offset in range(text_section_offset, text_section_offset+len(textSection)):
        inst_seq = linear_sweep(offset_inst_dict ,  byte_offset )
        if inst_seq== None:
            continue

        SEQUENCES.append(inst_seq)
        if byte_offset in ground_truth_offsets:
            LABELS.append(float(0))
        else:
            LABELS.append(float(1))



# In[8]:


print(len(SEQUENCES) , len(LABELS))
print(LABELS.count(0), LABELS.count(1))


# In[9]:


SEQUENCES[0]


# In[10]:


import sys,os

from transformers import BertTokenizer,BertForSequenceClassification

# If using a character-level tokenizer for sequences like DNA/Protein:
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")#BertTokenizer.from_pretrained('bert-base-uncased')

tokenizer = tokenizer.train_new_from_iterator(SEQUENCES, 2000)


model = BertForSequenceClassification.from_pretrained(
    'bert-base-uncased',
    num_labels=1  
)

model.to(device)


optim = AdamW( model.parameters() , lr=1e-5, eps = 1e-6, betas=(0.9,0.98), weight_decay=0.01)



# In[ ]:





# In[11]:


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
        
        # Convert tokens to input IDs
#         input_ids = self.tokenizer.convert_tokens_to_ids(tokenized_text)
        
        # Create input tensors
#         input_ids = tokenized_text['input_ids']  #torch.tensor(input_ids)
        # label = torch.tensor([label]).to(device)
        return tokenized_text, label
        
#         return {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
    def __len__(self):
        return len(self.texts)


# In[12]:


dataset = BinaryDataset(SEQUENCES, LABELS,tokenizer)
train_size = int(0.8 * len(dataset))
validation_size = len(dataset) - train_size

train_dataset, validation_dataset = torch.utils.data.random_split(dataset, [train_size, validation_size] , generator=torch.Generator().manual_seed(42))


# In[13]:


print(len(dataset))


# In[14]:


train_loader      = torch.utils.data.DataLoader(train_dataset, batch_size=BATCH_SIZE ,shuffle=True) 
validation_loader = torch.utils.data.DataLoader(validation_dataset, batch_size=BATCH_SIZE, shuffle=True)


# In[15]:


model, optim, train_loader,validation_loader = accelerator.prepare(model, optim, train_loader,validation_loader)


# In[16]:


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
        predictions = torch.argmax(logits, dim=1)

        # print(logits)

        # print(logits.squeeze())

        prediction_s.extend(predictions.detach().cpu().numpy().flatten())
        ground_truth_s.extend(batch_labels.detach().cpu().numpy().flatten())


        if is_training == True:
            # loss.backward()
            accelerator.backward(loss)
            optim.step()
        # print relevant info to progress bar
        data_loop.set_description(f'Epoch {ecpoch}')
        data_loop.set_postfix(loss=loss.item())

    ###### Training Scores
    # accuracy = accuracy_score(ground_truth_s, prediction_s)    
    # precision, recall, f1, _ = precision_recall_fscore_support(ground_truth_s,prediction_s,average='weighted')

    # Evaluation Metrics
    mse = mean_squared_error(ground_truth_s, prediction_s)
    rmse = sqrt(mse)
    mae = mean_absolute_error(ground_truth_s, prediction_s)
    r2 = r2_score(ground_truth_s, prediction_s)
    
    # print(f"MSE: {mse:.4f}")
    # print(f"RMSE: {rmse:.4f}")
    # print(f"MAE: {mae:.4f}")
    # print(f"R²: {r2:.4f}")


    metrices = {'MSE':mse ,
                      'RMSE':rmse, 
                      'MAE':mae, 
                      'R²':r2,
                      'loss': (sum(losses) / len(losses))}
    return metrices , prediction_s, ground_truth_s


# In[17]:


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
        print('v_metrices: ',v_metrices)
        v_global_metrices.append(v_metrices)


# In[ ]:


#jupyter nbconvert --to script data_pipe.ipynb


# In[ ]:




