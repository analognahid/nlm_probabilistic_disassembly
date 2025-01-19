# Importing required module
import subprocess
import concurrent.futures
from os import walk
import os, signal
from os import listdir
from os.path import isfile, join
import  os
import multiprocessing
from fnmatch import fnmatch
import sys
import tlsh, json


root    ='/media/raisul/nahid_personal/clones_100k'

bin_path = '/home/raisul/probabilistic_disassembly/objs'



manager = multiprocessing.Manager()
Global = manager.Namespace()

Global.total_c_compile = 0
Global.total_make = 0


c_pattern = "*.c"
makefile_pattern = "makefile"


def create_bin_path(src_path , bin_save_path):
      
    thash = tlsh.hash(open(src_path, 'rb').read())
    bin_output_path = os.path.join(bin_save_path ,thash )
    return thash, bin_output_path


def compile(src_file_path):

    try:
        thash, bin_output_path = create_bin_path(src_file_path, bin_path)
        src_dir_path, src_file_name = os.path.split(os.path.abspath(src_file_path))
        compiler = ' gcc '
        flags = ' -gdwarf-4 -O2  -c '


        if os.path.isfile(bin_output_path):
            return

        command = compiler + flags + '-o '+ bin_output_path +'.o '+ src_file_path
        print(command)
        process = subprocess.Popen(command ,shell=True) 
        
        Global.total_make  = Global.total_make  +1
        process.wait(timeout=10)

    except Exception as e:
         print (e)
##############################################






import pickle


all_c_paths = []

all_make_dir_paths = []

for path, subdirs, files in os.walk(root):

    if len(all_c_paths)%1000==0 and len(all_c_paths)>0:
         print("Now" , len(all_c_paths))
         break
    for name in files:
        file_path = os.path.join(path, name)
        

        if fnmatch(name.lower(), c_pattern):
                    c_file_path = os.path.join(path, name)
                    all_c_paths.append(c_file_path)
                    
        elif fnmatch(name.lower(), makefile_pattern):
                    all_make_dir_paths.append( path)



# with open('c_files_n_projs.ignore.pkl', 'wb') as f:
#     pickle.dump([all_c_paths,all_make_dir_paths] , f)
    
# with open('c_files_n_projs.ignore.pkl', 'rb') as file:
#     all_c_paths,all_make_dir_paths  = pickle.load(file)  





if __name__ == "__main__":  # Allows for the safe importing of the main module
    print("There are {} CPUs on this machine".format( multiprocessing.cpu_count()))
    number_processes = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(number_processes)
    results = pool.map_async(compile, all_c_paths[0:10])
    pool.close()
    pool.join()


