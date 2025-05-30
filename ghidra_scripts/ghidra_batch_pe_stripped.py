
import os


import posixpath
import sys,os,pickle


from collections import defaultdict

import collections
import posixpath

# unset GTK_PATH
import ntpath
from capstone import *
from capstone.x86 import *
import collections
import magic ,hashlib
import subprocess
from subprocess import STDOUT, check_output


BIN_PATH  = '/home/raisul/DATA/x86_pe_msvc_O2_static_stripped/' 

output_dir_path = '/home/raisul/ANALYSED_DATA/ghidra_x86_pe_msvc_O2_static_stripped/'






def analyse(  binary_path ):

    output_file_path = os.path.join(output_dir_path , os.path.basename(binary_path).split('.')[0]+'.json' ) 
    if os.path.isfile(output_file_path): #file already analysed
        return





    ghidra_path = '/home/raisul/re_tools/ghidra_11.1.2_PUBLIC_20240709/ghidra_11.1.2_PUBLIC/support/analyzeHeadless   '
    ghidra_proj_path = '/home/raisul/ANALYSED_DATA/ghidra_temp/{}'.format(output_file_path)
    ghidra_process = "  ghidraBenchmarking_MainProcess  "
    bin_path = "-import {} -overwrite  ".format(binary_path) 
    scripts = " -scriptPath /home/raisul/probabilistic_disassembly/ghidra_scripts -preScript dwarf_line.py -postScript ghidra_extract_pe.py '{}' -deleteProject".format(output_file_path) 



    command = ghidra_path + ghidra_proj_path + ghidra_process + bin_path + scripts
    print(command)
    
    if not os.path.isdir(ghidra_proj_path):
        os.makedirs(ghidra_proj_path)

    cmd_process = subprocess.Popen(command, shell=True)

    (output, err) = cmd_process.communicate()  
    # #This makes the wait possible
    p_status = cmd_process.wait(timeout=10)
    cmd_process.kill()

filtered_files  = [ os.path.join(BIN_PATH, f) for f in os.listdir(BIN_PATH) ]
filtered_files.sort()


import multiprocessing
from multiprocessing import active_children

if __name__ == "__main__":  # Allows for the safe importing of the main module
    print("There are {} CPUs on this machine".format( multiprocessing.cpu_count()))
    
    number_processes = 250 #int(multiprocessing.cpu_count() *0.1 )
    pool = multiprocessing.Pool(number_processes)


    results = pool.map_async(analyse, filtered_files)
    pool.close()
    pool.join()

    print(" DONE ALL SUCCESSFULLY Alhamdulillah"*50)

