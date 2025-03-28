import os, shutil

BIN_PATH = "/home/raisul/DATA/x86_pe_msvc_O2_static_stripped/" #

filtered_files  = [f for f in os.listdir(BIN_PATH) if f.endswith(".exe")] #os.path.join(BIN_PATH, f)

for pe_file in filtered_files:

    group_name = pe_file.split('.exe')[0]
    group_dir_path = os.path.join(BIN_PATH , group_name )

    src_pe_path = os.path.join(BIN_PATH , group_name+'.exe')
    # src_pdb_path = os.path.join(BIN_PATH , group_name+'.pdb')
    # src_ilk_path = os.path.join(BIN_PATH , group_name+'.ilk')

    if os.path.isdir(group_dir_path):
        print("Directory exists.")
    else:
        try:
            os.makedirs(group_dir_path)
            shutil.move(src_pe_path, group_dir_path)
            # shutil.move(src_pdb_path, group_dir_path)
            # shutil.move(src_ilk_path, group_dir_path)
            print('moved', group_dir_path)
        except Exception as e:
            print(e)
            continue