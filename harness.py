import os
import argparse
import subprocess
import time
import csv
import glob
import pandas as pd
import numpy
import lief
from subprocess import DEVNULL, STDOUT
parser = argparse.ArgumentParser(description="""\
A program to help you to automatically create fuzzing harnesses.         
""")
parser.add_argument('-L', '--library', help = "Specify directory to program's libraries", required=True)
parser.add_argument('-C', '--ql', help = "Specify directory of codeql modules, database, and binary", required=True)
parser.add_argument('-D', '--database', help = "Specify Codeql database", required=True)
parser.add_argument('-M', '--mode', help = "Specify 0 for 1 argument harnesses or 1 for multiple argument harnesses", required=True)
parser.add_argument('-O', '--output', help = "Output directory", required=True)
parser.add_argument('-F', '--flags', help = "Specify compiler flags (include)", required=False)
parser.add_argument('-X', '--headers', help = "Specify header files (comma seperated)", required=False)
parser.add_argument('-G', '--debug', help = "Specify 0/1 for disabling/enabling debug mode.", required=True)
args = parser.parse_args()
shared_objects=[]
object_functions={"output":[],"object":[]}
total_functions={"function":[], "type":[],"function_type":[]}
defined_functions={"function":[], "type":[],"object": [],"function_type":[]}
elf_functions={"function":[], "type":[],"object": [],"function_type":[]}
shared_functions={"function":[], "type":[],"object": [],"function_type":[]}
if (int(args.mode) == 0):
    cwd = os.getcwd()
    subprocess.check_output("cp " + cwd + "/onearg.ql " + args.ql, shell=True)
    subprocess.check_output("cd "+ args.ql + ";" +args.ql+ "codeql query run onearg.ql -o " + args.output + "onearg.bqrs -d " + args.ql + args.database +";" + args.ql + "codeql bqrs decode --format=csv " + args.output + "onearg.bqrs -o " + args.output + "onearg.csv", shell=True)
    os.chdir(args.library)
    for filename in os.listdir(args.library):
        if "shared object" in subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8'):
            print("Found shared object " + filename)
            shared_objects.append(filename)
    for x in shared_objects:
        object_functions["output"].append(subprocess.run(["readelf", "-a",x], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        object_functions["object"].append(x)
    data = pd.read_csv(args.output + "onearg.csv")
    total_functions["function"] = list(data.f)
    total_functions["type"] = list(data.s)
    total_functions["function_type"] = list(data.g)
    for index, defe in enumerate(object_functions["output"]):
        for index2, cur in enumerate(total_functions["function"]):
            if (str(cur) in defe):
                defined_functions["function"].append(cur)
                defined_functions["type"].append(total_functions["type"][index2])
                defined_functions["object"].append(object_functions["object"][index])
                defined_functions["function_type"].append(total_functions["function_type"][index2])
    for i in range(len(defined_functions["function"])):
        if ".so" not in str(defined_functions["object"][i]):
            elf = lief.parse(str(defined_functions["object"][i]))
            try:
                addr = elf.get_function_address(str(defined_functions["function"][i]))
            except: 
                continue
            elf.add_exported_function(addr, str(defined_functions["function"][i]))
            elf[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE) 
            outfile = "lib%s.so" % str(defined_functions["function"][i])
            elf.write(outfile)
            elf_functions["function"].append(str(defined_functions["function"][i]))
            elf_functions["type"].append(str(defined_functions["type"][i]))
            elf_functions["object"].append(outfile)
            elf_functions["function_type"].append(str(defined_functions["function_type"][i]))
        else:
            shared_functions["function"].append(str(defined_functions["function"][i]))
            shared_functions["type"].append(str(defined_functions["type"][i]))
            shared_functions["object"].append(str(defined_functions["object"][i]))
            shared_functions["function_type"].append(str(defined_functions["function_type"][i]))
    for index3 in range(len(shared_functions["function"])):
        header_section = ""
        if not args.headers:
            header_section = ""
        else: 
            header_list = args.headers.split(",")
            for x in header_list:
                header_section+= "#include \"" + x + "\"\n\n"
        main_section = str(shared_functions["function_type"][index3]) + " " + str(shared_functions["function"][index3]) + "(" + str(shared_functions["type"][index3])+ " testcase);\n" + "int LLVMFuzzerTestOneInput(" + str(shared_functions["type"][index3]) + " Data, long Size) {\n\t" + str(shared_functions["function"][index3]) + "(Data);\n\treturn 0;\n}"
        full_source = header_section + main_section
        filename = "".join([c for c in str(shared_functions["function"][index3]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
        f = open(args.output + filename +".c", "w")
        f.write(full_source)
        if args.flags is not None and int(args.debug) == 1:
            env = os.environ.copy()
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True)
        elif args.flags is not None and int(args.debug) == 0:
            env = os.environ.copy()
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        elif args.flags is None and int(args.debug) == 1:
           env = os.environ.copy()
           subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True)
        else:
           env = os.environ.copy()
           subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
    for index4 in range(len(elf_functions["function"])):
        header_section = ""
        if not args.headers:
            header_section = ""
        else: 
            header_list = args.headers.split(",")
            for x in header_list:
                header_section+= "#include \"" + x + "\"\n\n"
        main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["function_type"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + str(elf_functions["type"][index4]) + ");\n" + "void CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + args.library + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nint LLVMFuzzerTestOneInput(" + str(elf_functions["type"][index4]) + " Data, long Size) {\n\tLoadLibrary();\n\t" + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(Data);\n\treturn 0;\n}"
        full_source = header_section + main_section
        filename = "".join([c for c in str(elf_functions["function"][index4]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
        f = open(args.output + filename +".c", "w")
        f.write(full_source)
        if args.flags is not None and int(args.debug) == 1:
            env = os.environ.copy()
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True)
        elif args.flags is not None and int(args.debug) == 0:
            env = os.environ.copy()
            subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        elif args.flags is None and int(args.debug) == 1:
           env = os.environ.copy()
           subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True)
        else:
           env = os.environ.copy()
           subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
    if int(args.debug) == 0:
        subprocess.Popen("rm *.c", env=env, shell=True)
elif (int(args.mode) == 1):
    print("bob")
else:
    print("Invalid Mode")
    
