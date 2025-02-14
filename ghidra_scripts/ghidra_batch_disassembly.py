
import os, random 

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
import posixpath
import sys,os,pickle
from elftools.elf.segments import Segment
from elftools.dwarf.locationlists import LocationParser, LocationExpr

from collections import defaultdict

import collections
import posixpath
from os import listdir
from os.path import isfile, join


import ntpath
from capstone import *
from capstone.x86 import *
import collections
import magic ,hashlib
import subprocess
from subprocess import STDOUT, check_output


BIN_PATH  = '/home/raisul/probabilistic_disassembly/blobs/'

output_dir_path = '/home/raisul/probabilistic_disassembly/ghidara_output/'



def analyse(  binary_path ):


    binary_file_name = os.path.basename(binary_path)
    output_file_path = os.path.join(output_dir_path , binary_file_name ) 


    # if os.path.isfile(output_file_path): #file already analysed
    #     return

    ghidra_path = ' /home/raisul/re_tools/ghidra_11.1.2_PUBLIC_20240709/ghidra_11.1.2_PUBLIC/support/analyzeHeadless   '
    ghidra_proj_path = '/media/raisul/nahid_personal/dwarf4/ghidra_types/temp_proj/{}'.format(binary_file_name)
    ghidra_process = "  ghidraBenchmarking_MainProcess  "
    bin_path = "-import {} -overwrite  ".format(binary_path) 
    scripts = " -scriptPath /home/raisul/tokenization/data_creation -preScript dwarf_line.py -postScript ghidra_script_disassemble.py '{}' -deleteProject".format(output_file_path) 
    # -preScript dwarf_line.py

    command = ghidra_path + ghidra_proj_path + ghidra_process + bin_path + scripts

    if not os.path.isdir(ghidra_proj_path):
        os.makedirs(ghidra_proj_path)
        # os.makedirs(os.path.join( ghidra_proj_path,'ghidraBenchmarking_MainProcess' ))
    
    

    cmd_process = subprocess.Popen(command, shell=True)



    (output, err) = cmd_process.communicate()  
    # #This makes the wait possible
    p_status = cmd_process.wait(timeout=10)
    cmd_process.kill()






filtered_files = [join(BIN_PATH, f) for f in listdir(BIN_PATH) if isfile(join(BIN_PATH, f))]
# random.shuffle(filtered_files)
# filtered_files = filtered_files [0:2]



import multiprocessing
from multiprocessing import active_children

if __name__ == "__main__":  # Allows for the safe importing of the main module
    print("There are {} CPUs on this machine".format( multiprocessing.cpu_count()))
    
    number_processes = int(multiprocessing.cpu_count() *1.25 )
    pool = multiprocessing.Pool(number_processes)

    # filtered_files = filtered_files[0:200]
    results = pool.map_async(analyse, filtered_files)
    pool.close()
    pool.join()

    print(" DONE ALL SUCCESSFULLY Alhamdulillah"*10)

