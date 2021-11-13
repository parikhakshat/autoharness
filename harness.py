import os
import argparse
import subprocess
import pandas as pd
import lief
from subprocess import DEVNULL, STDOUT
from ast import literal_eval
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
parser.add_argument('-Y', '--detection', help = "Automatic header detection (0) or Function Definition (1).", required=True)
args = parser.parse_args()
def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)
if (int(args.mode) == 0):
    shared_objects=[]
    object_functions={"output":[],"object":[]}
    total_functions={"function":[], "type":[],"type_or_loc":[]}
    defined_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    elf_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    shared_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    cwd = os.getcwd()
    if int(args.detection) == 0:
        subprocess.check_output("cp " + cwd + "/onearglocation.ql " + args.ql, shell=True)
        subprocess.check_output("cd "+ args.ql + ";" +args.ql+ "codeql query run onearglocation.ql -o " + args.output + "onearg.bqrs -d " + args.ql + args.database +";" + args.ql + "codeql bqrs decode --format=csv " + args.output + "onearg.bqrs -o " + args.output + "onearg.csv", shell=True)
    elif int(args.detection) == 1:
       subprocess.check_output("cp " + cwd + "/oneargfunc.ql " + args.ql, shell=True)
       subprocess.check_output("cd "+ args.ql + ";" +args.ql+ "codeql query run oneargfunc.ql -o " + args.output + "onearg.bqrs -d " + args.ql + args.database +";" + args.ql + "codeql bqrs decode --format=csv " + args.output + "onearg.bqrs -o " + args.output + "onearg.csv", shell=True)
    os.chdir(args.library)
    matches = ["shared object","pie executable"]
    for filename in os.listdir(args.library):
        if any(x in subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8') for x in matches):
            print("Found shared object " + filename)
            shared_objects.append(filename)
    for obj in shared_objects:
        object_functions["output"].append(subprocess.run(["readelf", "-a",obj], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        object_functions["object"].append(obj)
    data = pd.read_csv(args.output + "onearg.csv")
    total_functions["function"] = list(data.f)
    total_functions["type"] = list(data.t)
    total_functions["type_or_loc"] = list(data.g)
    for index, define in enumerate(object_functions["output"]):
        for index2, cur in enumerate(total_functions["function"]):
            if (str(cur) in define):
                defined_functions["function"].append(cur)
                defined_functions["type"].append(total_functions["type"][index2])
                defined_functions["object"].append(object_functions["object"][index])
                defined_functions["type_or_loc"].append(total_functions["type_or_loc"][index2])
    for i in range(len(defined_functions["function"])):
        if ".so" not in str(defined_functions["object"][i]):
            elf = lief.parse(args.library + str(defined_functions["object"][i]))
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
            elf_functions["type_or_loc"].append(str(defined_functions["type_or_loc"][i]))
        else:
            shared_functions["function"].append(str(defined_functions["function"][i]))
            shared_functions["type"].append(str(defined_functions["type"][i]))
            shared_functions["object"].append(str(defined_functions["object"][i]))
            shared_functions["type_or_loc"].append(str(defined_functions["type_or_loc"][i]))
    for index3 in range(len(shared_functions["function"])):
        header_section = ""
        if not args.headers:
            if int(args.detection) == 0:
                header_section = "#include \"" + os.path.basename(shared_functions["type_or_loc"][index3]) + "\"\n\n"
            else:
                header_section = ""
        else: 
            header_list = args.headers.split(",")
            for x in header_list:
                header_section+= "#include \"" + x + "\"\n\n"
                
        if int(args.detection) == 0: 
            main_section = "int LLVMFuzzerTestOneInput(" + str(shared_functions["type"][index3]) + " Data, long Size) {\n\t" + str(shared_functions["function"][index3]) + "(Data);\n\treturn 0;\n}"
        else: 
           main_section = str(shared_functions["type_or_loc"][index3]) + " " + str(shared_functions["function"][index3]) + "(" + str(shared_functions["type"][index3])+ " testcase);\n" + "int LLVMFuzzerTestOneInput(" + str(shared_functions["type"][index3]) + " Data, long Size) {\n\t" + str(shared_functions["function"][index3]) + "(Data);\n\treturn 0;\n}" 
        full_source = header_section + main_section
        filename = "".join([c for c in str(shared_functions["function"][index3]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
        f = open(args.output + filename +".c", "w")
        f.write(full_source)
        if int(args.detection) == 0:
            if args.flags is not None and int(args.debug) == 1:
                env = os.environ.copy()
                subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True)
            elif args.flags is not None and int(args.debug) == 0:
                env = os.environ.copy()
                subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif args.flags is None and int(args.debug) == 1:
               env = os.environ.copy()
               subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True)
            else:
               env = os.environ.copy()
               subprocess.Popen("clang -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".c -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        else:
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
    if (int(args.detection) == 1):
        for index4 in range(len(elf_functions["function"])):
            header_section = ""
            if not args.headers:
                    header_section = ""
            else: 
                header_list = args.headers.split(",")
                for x in header_list:
                    header_section+= "#include \"" + x + "\"\n\n"               
            main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["type_or_loc"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + str(elf_functions["type"][index4]) + ");\n" + "void CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + args.library + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nint LLVMFuzzerTestOneInput(" + str(elf_functions["type"][index4]) + " Data, long Size) {\n\tLoadLibrary();\n\t" + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(Data);\n\treturn 0;\n}"
            full_source = header_section + main_section
            filename = "".join([c for c in str(elf_functions["function"][index4]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
            f = open(args.output + filename +".c", "w")
            f.write(full_source)
            if args.flags is not None and int(args.debug) == 1:
                env = os.environ.copy()
                print("clang -g -fsanitize=address,undefined,fuzzer " + args.flags + " " + args.output + filename +".c -o " + args.output + filename)
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
elif (int(args.mode) == 1):
    shared_objects=[]
    func_objects=[]
    object_functions={"output":[],"object":[]}
    cwd = os.getcwd()
    if (int(args.detection) == 0):
        subprocess.check_output("cp " + cwd + "/multiarglocation.ql " + args.ql, shell=True)
        subprocess.check_output("cd "+ args.ql + ";" +args.ql+ "codeql query run multiarglocation.ql -o " + args.output + "multiarg.bqrs -d " + args.ql + args.database +";" + args.ql + "codeql bqrs decode --format=csv " + args.output + "multiarg.bqrs -o " + args.output + "multiarg.csv", shell=True)
    elif (int(args.detection) == 1):
        subprocess.check_output("cp " + cwd + "/multiargfunc.ql " + args.ql, shell=True)
        subprocess.check_output("cd "+ args.ql + ";" +args.ql+ "codeql query run multiargfunc.ql -o " + args.output + "multiarg.bqrs -d " + args.ql + args.database +";" + args.ql + "codeql bqrs decode --format=csv " + args.output + "multiarg.bqrs -o " + args.output + "multiarg.csv", shell=True)
    data = pd.read_csv(args.output + "multiarg.csv")
    total_functions = data.drop_duplicates().groupby(["f", "g"], as_index=False)["t"].agg(list)
    print(total_functions)
    os.chdir(args.library)
    defined_functions = pd.DataFrame(columns=["f","t","g","object"])
    matches = ["shared object","pie executable"]
    for filename in os.listdir(args.library):
        if any(x in subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8') for x in matches):
            print("Found shared object " + filename)
            shared_objects.append(filename)
    for obj in shared_objects:
        object_functions["output"].append(subprocess.run(["readelf", "-a",obj], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        object_functions["object"].append(obj)
    for index, defe in enumerate(object_functions["output"]):
        for index2, cur in enumerate(total_functions["f"]):
            if (str(cur) in defe):
                func_objects.append(object_functions["object"][index])
                defined_functions = defined_functions.append([total_functions.iloc[index2,:]])
    defined_functions["object"] = func_objects
    defined_functions = defined_functions.to_dict(orient='list')
    elf_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    shared_functions={"function":[], "type":[],"object": [],"type_or_loc":[]}
    for i in range(len(defined_functions["f"])):
        if ".so" not in str(defined_functions["object"][i]):
            elf = lief.parse(args.library + str(defined_functions["object"][i]))
            try:
                addr = elf.get_function_address(str(defined_functions["f"][i]))
            except: 
                continue
            elf.add_exported_function(addr, str(defined_functions["f"][i]))
            elf[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE) 
            outfile = "lib%s.so" % str(defined_functions["f"][i])
            elf.write(outfile)
            elf_functions["function"].append(str(defined_functions["f"][i]))
            elf_functions["type"].append(str(defined_functions["t"][i]))
            elf_functions["object"].append(outfile)
            elf_functions["type_or_loc"].append(str(defined_functions["g"][i]))
        else:
            shared_functions["function"].append(str(defined_functions["f"][i]))
            shared_functions["type"].append(str(defined_functions["t"][i]))
            shared_functions["object"].append(str(defined_functions["object"][i]))
            shared_functions["type_or_loc"].append(str(defined_functions["g"][i]))
    for index3 in range(len(shared_functions["function"])):
        header_section = ""
        if not args.headers:
            if (int(args.detection) == 0):
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n" + "#include \"" + os.path.basename(shared_functions["type_or_loc"][index3]) + "\"\n\n"
            else:
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"            
        else: 
            header_list = args.headers.split(",")
            header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
            for x in header_list:
                header_section+= "#include \"" + x + "\"\n\n"
        stub = ""
        marker = 1
        param = ""
        header_args = ""
        for ty in literal_eval(shared_functions["type"][index3]):
            if ty.count('*') == 1:
                if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" 
                   param += "pointer" + str(marker) + ", "
                   header_args += ty + "pointer" + str(marker) + ", "
                elif "char" in ty or "string" in ty:
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                   param += "pointer" + str(marker) + ", "
                   header_args += ty + "pointer" + str(marker) + ", "
                elif "float" in ty or "double" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") +">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                    param += "pointer" + str(marker) + ", "
                    header_args += ty + "pointer" + str(marker) + ", "
                elif "bool" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty + "pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                    param += "pointer" + str(marker) + ", "
                    header_args += ty + "pointer" + str(marker) + ", "
                else: 
                    continue    
            elif ty.count('*') == 2:
                if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                   param += "doublepointer" + str(marker) + ", "
                   header_args += ty + "doublepointer" + str(marker) + ", "
                elif "char" in ty or "string" in ty:
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n" 
                   param += "doublepointer" + str(marker) + ", "
                   header_args += ty + "doublepointer" + str(marker) + ", "
                elif "float" in ty or "double" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                    param += "doublepointer" + str(marker) + ", "
                    header_args += ty + "doublepointer" + str(marker) + ", "
                elif "bool" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty.replace("*", "") + "*pointer" + str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"    
                    param += "doublepointer" + str(marker) + ", "
                    header_args += ty + "doublepointer" + str(marker) + ", "                    
                else: 
                    continue
            else:
                if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n" 
                   param += "data" + str(marker) + ", "
                   header_args += ty + " data" + str(marker) + ", "
                elif "char" in ty or "string" in ty:
                   stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n"
                   param += "data" + str(marker) + ", "
                   header_args += ty + " data" + str(marker) + ", "
                elif "float" in ty or "double" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty +">();\n"
                    param += "data" + str(marker) + ", "
                    header_args += ty + " data" + str(marker) + ", "
                elif "bool" in ty:
                    stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n"
                    param += "data" + str(marker) + ", "
                    header_args += ty + " data" + str(marker) + ", "
                else: 
                    continue
            marker+= 1
        param = rreplace(param,', ','',1)
        header_args = rreplace(header_args,', ','',1)
        if (int(args.detection) == 0):
            main_section = "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t" + stub + str(shared_functions["function"][index3]) + "(" + param + ");\nreturn 0;\n}"
        else:
            main_section = str(shared_functions["type_or_loc"][index3]) + " " + str(shared_functions["function"][index3]) +"(" + header_args + ");\n\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t" + stub + str(shared_functions["function"][index3]) + "(" + param + ");\nreturn 0;\n}"
        full_source = header_section + main_section
        filename = "".join([c for c in str(shared_functions["function"][index3]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
        f = open(args.output + filename +".cc", "w")
        f.write(full_source)
        if int(args.detection) == 0:
            if args.flags is not None and int(args.debug) == 1:
                env = os.environ.copy()
                print("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename)
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True)
            elif args.flags is not None and int(args.debug) == 0:
                env = os.environ.copy()
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif args.flags is None and int(args.debug) == 1:
               env = os.environ.copy()
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True)
            else:
               env = os.environ.copy()
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -I" + os.path.dirname(shared_functions["type_or_loc"][index3]) + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
        else:
            if args.flags is not None and int(args.debug) == 1:
                env = os.environ.copy()
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True)
            elif args.flags is not None and int(args.debug) == 0:
                env = os.environ.copy()
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif args.flags is None and int(args.debug) == 1:
               env = os.environ.copy()
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True)
            else:
               env = os.environ.copy()
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer -L " + args.output + " -L " +args.library + " -l:" + str((shared_functions["object"][index3])) + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
    if (int(args.detection) == 1):
        for index4 in range(len(elf_functions["function"])):
            header_section = ""
            if not args.headers:
                    header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"            
            else: 
                header_list = args.headers.split(",")
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                for x in header_list:
                    header_section+= "#include \"" + x + "\"\n"
            stub = ""
            marker = 1
            param = ""
            header_args = ""
            for ty in literal_eval(elf_functions["type"][index4]):
                if ty.count('*') == 1:
                    if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" 
                       param += "pointer" + str(marker) + ", "
                       header_args += ty + "pointer" + str(marker) + ", "
                    elif "char" in ty or "string" in ty:
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                       param += "pointer" + str(marker) + ", "
                       header_args += ty + "pointer" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") +">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    elif "bool" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty + "pointer"+ str(marker) + " = &data" + str(marker) + ";\n"
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    else: 
                        continue    
                elif ty.count('*') == 2:
                    if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                       param += "doublepointer" + str(marker) + ", "
                       header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "char" in ty or "string" in ty:
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n" 
                       param += "doublepointer" + str(marker) + ", "
                       header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty.replace("*", "") + ">();\n" + ty.replace("*", "") + "*pointer"+ str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"  
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "bool" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n" + ty.replace("*", "") + "*pointer" + str(marker) + " = &data" + str(marker) + ";\n" + ty.replace("*", "") + "**doublepointer"+str(marker) + " = &pointer"+ str(marker) + ";\n"    
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "                    
                    else: 
                        continue
                else:
                    if "long" in ty or "int" in ty or "short" in ty and "long double" not in ty:  
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n" 
                       param += "data" + str(marker) + ", "
                       header_args += ty + " data" + str(marker) + ", "
                    elif "char" in ty or "string" in ty:
                       stub  += "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty +">();\n"
                       param += "data" + str(marker) + ", "
                       header_args += ty + " data" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeFloatingPoint<" + ty +">();\n"
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    elif "bool" in ty:
                        stub  += "auto data" + str(marker) + "= provider.ConsumeBool();\n"
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    else: 
                        continue
                marker+= 1
            param = rreplace(param,', ','',1)
            header_args = rreplace(header_args,', ','',1)
            main_section = "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef " + str(elf_functions["type_or_loc"][index4]) + "(*" + str(elf_functions["function"][index4]) + "_t)(" + header_args + ");\nvoid CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen(\"" + args.library + str(elf_functions["object"][index4]) + "\",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t\n\tLoadLibrary();\n\t" + stub + str(elf_functions["function"][index4]) + "_t " + str(elf_functions["function"][index4]) + "_s = (" + str(elf_functions["function"][index4]) + "_t)dlsym(library,\"" + str(elf_functions["function"][index4]) + "\");\n\t" + str(elf_functions["function"][index4]) + "_s(" + param + ");\n\treturn 0;\n}" 
            full_source = header_section + main_section
            filename = "".join([c for c in str(elf_functions["function"][index4]) if c.isalpha() or c.isdigit() or c==' ']).rstrip()
            f = open(args.output + filename +".cc", "w")
            f.write(full_source)
            if args.flags is not None and int(args.debug) == 1:
                env = os.environ.copy()
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True)
            elif args.flags is not None and int(args.debug) == 0:
                env = os.environ.copy()
                subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.flags + " " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT)
            elif args.flags is None and int(args.debug) == 1:
               env = os.environ.copy()
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True)
            else:
               env = os.environ.copy()
               subprocess.Popen("clang++ -g -fsanitize=address,undefined,fuzzer " + args.output + filename +".cc -o " + args.output + filename, env=env, shell=True, stdout=DEVNULL, stderr=STDOUT) 
else:
    print("Invalid Mode")
