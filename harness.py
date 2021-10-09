#!/usr/bin/env python3

import os
import argparse
import subprocess
from typing import cast
import pandas as pd
import re
import lief
from subprocess import DEVNULL, STDOUT
from ast import literal_eval

import harness_argparser
import command_builder as cb
# import source_builder as sb  # TODO: factor out code into a separate file/module

DEBUG = False
SKIP_CODEGEN = False

arg_parser = harness_argparser.create_parser()
args = arg_parser.parse_args()

# The function "signature" has arguments like "int[8] var" which should be changed
# into "int var[8]" for the parameters of a harness function.
def fun_signature_to_params(signature):
    """Take a function signature and return a string that can be used for the parameters in the harness template."""
    # Create a list of the separate arguments
    sig_list = signature.strip(', \t').split(",")
    # A C++ identifier can be a type or variable name, among other things
    cpp_identifier = r"[a-zA-Z_][a-zA-Z0-9_]*"
    # Regex to capture a single argument, with the array-brackets in a separate group to move to the end.
    arg_regex = r"((?:[a-z]+\s+)*" + cpp_identifier + "\s*\**)\s*(\[\d+\])\s*(" + cpp_identifier + ")"
    param_list = []
    for sig_idx, sig in enumerate(sig_list):
        sig = sig.strip()
        mygroup = re.match(arg_regex, sig)
        if mygroup is None:
            # print("no array, just add sig: " + sig)
            param_list.append(sig)
        else:
            param_list.append(mygroup[1] + ' ' + mygroup[3] + mygroup[2])
    result = ", ".join(param_list)
    # print(f"result for {signature}: {result}")
    return result

def consume_array_data():
    pass

def rreplace(s):
    result = "".join(s.rsplit(", ", 1))
    return result

shared_objects = []
object_functions = {"output": [], "object": []}
cwd = os.getcwd()
env = os.environ.copy()

if int(args.debug) == 1:
    compile_stdout = None
    compile_stderr = None
elif int(args.debug) == 0:
    compile_stdout = DEVNULL
    compile_stderr = STDOUT

if int(args.mode) == 0:
    total_functions = {"function": [], "type": [], "type_or_loc": []}
    defined_functions = {"function": [], "type": [], "object": [], "type_or_loc": []}
    elf_functions = {"function": [], "type": [], "object": [], "type_or_loc": []}
    shared_functions = {"function": [], "type": [], "object": [], "type_or_loc": []}
    if int(args.detection) == 0:
        # subprocess.check_output("cp " + cwd + "/onearglocation.ql " + args.ql, shell=True)
        subprocess.check_output(cb.cp_onearglocation_to_ql(args), shell=True)
        subprocess.check_output(
            shell=True
        )
    elif int(args.detection) == 1:
        subprocess.check_output("cp " + cwd + "/oneargfunc.ql " + args.ql, shell=True)
        subprocess.check_output(
            "cd "
            + args.ql
            + ";"
            + args.ql
            + "codeql query run oneargfunc.ql -o "
            + args.output
            + "onearg.bqrs -d "
            + args.ql
            + args.database
            + ";"
            + args.ql
            + "codeql bqrs decode --format=csv "
            + args.output
            + "onearg.bqrs -o "
            + args.output
            + "onearg.csv",
            shell=True,
        )
    os.chdir(args.library_dir)
    for filename in os.listdir(args.library_dir):
        if "shared object" in subprocess.run(
            ["file", filename], stdout=subprocess.PIPE
        ).stdout.decode("utf-8"):
            print("Found shared object " + filename)
            shared_objects.append(filename)
    for obj in shared_objects:
        object_functions["output"].append(
            # subprocess.run(["readelf", "-Ws", obj], stdout=subprocess.PIPE).stdout.decode("utf-8")
            subprocess.run(["nm", "-Dg", "--defined-only", obj], stdout=subprocess.PIPE).stdout.decode("utf-8")
        )
        object_functions["object"].append(obj)
    data = pd.read_csv(args.output + "onearg.csv")
    total_functions["function"] = list(data.f)
    total_functions["type"] = list(data.t)
    total_functions["type_or_loc"] = list(data.g)
    for index, define in enumerate(object_functions["output"]):
        for index2, cur in enumerate(total_functions["function"]):
            if str(cur) in define: # TODO: make this robust
                defined_functions["function"].append(cur)
                defined_functions["type"].append(total_functions["type"][index2])
                defined_functions["object"].append(object_functions["object"][index])
                defined_functions["type_or_loc"].append(total_functions["type_or_loc"][index2])
    for i in range(len(defined_functions["function"])):
        if ".so" not in str(defined_functions["object"][i]):
            elf = lief.parse(args.library_dir + str(defined_functions["object"][i]))
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
                header_section = (
                    '#include "'
                    + os.path.basename(shared_functions["type_or_loc"][index3])
                    + '"\n\n'
                )
            else:
                header_section = ""
        else:
            header_list = args.headers.split(",")
            for x in header_list:
                header_section += '#include "' + x + '"\n\n'

        if int(args.detection) == 0:
            main_section = (
                "int LLVMFuzzerTestOneInput("
                + str(shared_functions["type"][index3])
                + " Data, long Size) {\n\t"
                + str(shared_functions["function"][index3])
                + "(Data);\n\treturn 0;\n}"
            )
        else:
            main_section = (
                str(shared_functions["type_or_loc"][index3])
                + " "
                + str(shared_functions["function"][index3])
                + "("
                + str(shared_functions["type"][index3])
                + " testcase);\n"
                + "int LLVMFuzzerTestOneInput("
                + str(shared_functions["type"][index3])
                + " Data, long Size) {\n\t"
                + str(shared_functions["function"][index3])
                + "(Data);\n\treturn 0;\n}"
            )
        full_source = header_section + main_section
        filename = "".join(
            [
                c
                for c in str(shared_functions["function"][index3])
                if c.isalpha() or c.isdigit() or c == " "
            ]
        ).rstrip()
        f = open(args.output + filename + ".c", "w")
        f.write(full_source)
        library_name = str((shared_functions["object"][index3]))
        headers_dir = None
        if args.detection == 0:
            headers_dir = os.path.dirname(shared_functions["type_or_loc"][index3])
        compile_command = cb.clang_command(args, filename, library_name, headers_dir)
        subprocess.Popen(
            compile_command,
            env=env,
            shell=True,
            stdout=DEVNULL,
            stderr=STDOUT,
        )
    if int(args.detection) == 1:
        for index4 in range(len(elf_functions["function"])):
            header_section = ""
            if not args.headers:
                header_section = ""
            else:
                header_list = args.headers.split(",")
                for x in header_list:
                    header_section += '#include "' + x + '"\n\n'
            main_section = (
                "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef "
                + str(elf_functions["type_or_loc"][index4])
                + "(*"
                + str(elf_functions["function"][index4])
                + "_t)("
                + str(elf_functions["type"][index4])
                + ");\n"
                + 'void CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen("'
                + args.library_dir
                + str(elf_functions["object"][index4])
                + '",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nint LLVMFuzzerTestOneInput('
                + str(elf_functions["type"][index4])
                + " Data, long Size) {\n\tLoadLibrary();\n\t"
                + str(elf_functions["function"][index4])
                + "_t "
                + str(elf_functions["function"][index4])
                + "_s = ("
                + str(elf_functions["function"][index4])
                + '_t)dlsym(library,"'
                + str(elf_functions["function"][index4])
                + '");\n\t'
                + str(elf_functions["function"][index4])
                + "_s(Data);\n\treturn 0;\n}"
            )
            full_source = header_section + main_section
            filename = "".join(
                [
                    c
                    for c in str(elf_functions["function"][index4])
                    if c.isalpha() or c.isdigit() or c == " "
                ]
            ).rstrip()
            f = open(args.output + filename + ".c", "w")
            f.write(full_source)
            print("WARNING: clang command does not include -L flag before args.output, possibly a bug?")
            compile_command = cb.clang_command_2(args, filename)
            subprocess.Popen(
                compile_command,
                env=env,
                shell=True,
                stdout=DEVNULL,
                stderr=STDOUT,
            )
elif int(args.mode) == 1:
    objects_containing_function = []
    if int(args.detection) == 0:
        # print("Detection == 0")
        subprocess.check_output("cp " + cwd + "/multiarglocation.ql " + args.ql, shell=True)
        subprocess.check_output(
            "cd "
            + args.ql
            + ";"
            + args.ql
            + "codeql query run multiarglocation.ql -o "
            + args.output
            + "multiarg.bqrs -d "
            + args.ql
            + args.database
            + ";"
            + args.ql
            + "codeql bqrs decode --format=csv "
            + args.output
            + "multiarg.bqrs -o "
            + args.output
            + "multiarg.csv",
            shell=True,
        )
    elif int(args.detection) == 1:
        # print("Detection == 1")
        # print("cp " + cwd + "/multiargfunc.ql " + args.ql)
        subprocess.check_output("cp " + cwd + "/multiargfunc.ql " + args.ql, shell=True)
        subprocess.check_output(
            "cd "
            + args.ql
            + ";"
            + args.ql
            + "codeql query run multiargfunc.ql -o "
            + args.output
            + "multiarg.bqrs -d "
            + args.ql
            + args.database
            + ";"
            + args.ql
            + "codeql bqrs decode --format=csv "
            + args.output
            + "multiarg.bqrs -o "
            + args.output
            + "multiarg.csv",
            shell=True,
        )
    data: pd.DataFrame = cast(pd.DataFrame, pd.read_csv(args.output + "multiarg.csv")).sort_values(['f', 'g', 'param_idx'])
    # total_functions = data.drop_duplicates().groupby(["f", "g"], as_index=False)["t"].agg(list)
    total_functions = data.drop_duplicates().groupby(["f", "g"], as_index=False)["t"].agg(list)
    os.chdir(args.library_dir)
    defined_functions = pd.DataFrame(columns=["f", "t", "g", "object"])
    # Identify shared objects
    for filename in os.listdir(args.library_dir):
        if "shared object" in subprocess.run(
            ["file", filename], stdout=subprocess.PIPE
        ).stdout.decode("utf-8"):
            print("Found shared object " + filename)
            shared_objects.append(filename)
    # Create dictionary with nm info for shared objects
    for obj in shared_objects:
        object_functions["output"].append(
            # subprocess.run(["readelf", "-Ws", obj], stdout=subprocess.PIPE).stdout.decode("utf-8")
            subprocess.run(["nm", "-Dg", "--defined-only", obj], stdout=subprocess.PIPE).stdout.decode("utf-8")
        )
        object_functions["object"].append(obj)
    # Get function names from shared objects
    for index, exported_functions_output in enumerate(object_functions["output"]):
        for fun_line in exported_functions_output.splitlines():
            for index2, current_function in enumerate(total_functions["f"]):
                # nm reports function name at fixed offset. Fragile but works for now.
                if current_function == fun_line[19:]:
                    objects_containing_function.append(object_functions["object"][index])
                    defined_functions = defined_functions.append([total_functions.iloc[index2, :]])
    defined_functions["object"] = objects_containing_function
    defined_functions = defined_functions.to_dict(orient="list")
    # print("DEFINED FUNCTIONS")
    # print(defined_functions["f"])
    elf_functions = {"function": [], "type": [], "object": [], "type_or_loc": []}
    shared_functions = {"function": [], "type": [], "object": [], "type_or_loc": []}
    for i in range(len(defined_functions["f"])):
        if ".so" not in str(defined_functions["object"][i]):
            print("Not a .so, do lief-magic to create one! - but exit for now, I have no idea when this gets used.")
            # exit()
            elf = lief.parse(args.library_dir + str(defined_functions["object"][i]))
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
    good_fun_count = 0
    bad_fun_count = 0
    for index3 in range(len(shared_functions["function"])):
        # if shared_functions["function"][index3] != "crypto_sign_edwards25519sha512batch_open":
        #     continue
        print("Processing function ", end='')
        # print(shared_functions["function"][index3])
        bad_fun = False
        if not SKIP_CODEGEN:
            header_section = ""
            if not args.headers:
                if int(args.detection) == 0:
                    header_section += (
                        "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                        + '#include "'
                        + os.path.basename(shared_functions["type_or_loc"][index3])
                        + '"\n\n'
                    )
                else:
                    header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
            else:
                header_list = args.headers.split(",")
                header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                for x in header_list:
                    header_section += '#include "' + x + '"\n\n'
            stub = ""
            marker = 1
            param = ""
            header_args = ""
            for ty in literal_eval(shared_functions["type"][index3]):
                if ty.count("[") > 0: # TODO: add array support
                    bad_fun_count += 1
                    bad_fun = True
                    break
                elif ty.count("*") == 1:
                    if ("long" in ty or "int" in ty or "short" in ty and "long double" not in ty) or (
                        "char" in ty or "string" in ty
                    ):
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeIntegral<"
                            + ty.replace("*", "")
                            + ">();\n"
                            # + ty.replace("*", "")
                            # + "*pointer"
                            + ty + " pointer"
                            + str(marker)
                            + " = &data"
                            + str(marker)
                            + ";\n"
                        )
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeFloatingPoint<"
                            + ty.replace("*", "")
                            + ">();\n"
                            + ty + " pointer"
                            + str(marker)
                            + " = &data"
                            + str(marker)
                            + ";\n"
                        )
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    elif "bool" in ty:
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeBool();\n"
                            + ty
                            + " pointer"
                            + str(marker)
                            + " = &data"
                            + str(marker)
                            + ";\n"
                        )
                        param += "pointer" + str(marker) + ", "
                        header_args += ty + "pointer" + str(marker) + ", "
                    else:
                        print("INFO: no match for parameter " + ty + " found, not creating a harness for function " + str(shared_functions["function"][index3]))
                        bad_fun = True
                        break
                elif ty.count("*") == 2:
                    if ("long" in ty or "int" in ty or "short" in ty and "long double" not in ty) or (
                        "char" in ty or "string" in ty
                    ):
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeIntegral<"
                            + ty.replace("*", "")
                            + ">();\n"
                            + ty.replace("*", "")
                            + "*pointer"
                            + str(marker)
                            + " = &data"
                            + str(marker)
                            + ";\n"
                            + ty.replace("*", "")
                            + "**doublepointer"
                            + str(marker)
                            + " = &pointer"
                            + str(marker)
                            + ";\n"
                        )
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeFloatingPoint<"
                            + ty.replace("*", "")
                            + ">();\n"
                            + ty.replace("*", "")
                            + "*pointer"
                            + str(marker)
                            + " = &data"
                            + str(marker)
                            + ";\n"
                            + ty.replace("*", "")
                            + "**doublepointer"
                            + str(marker)
                            + " = &pointer"
                            + str(marker)
                            + ";\n"
                        )
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "
                    elif "bool" in ty:
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeBool();\n"
                            + ty.replace("*", "")
                            + "*pointer"
                            + str(marker)
                            + " = &data"
                            + str(marker)
                            + ";\n"
                            + ty.replace("*", "")
                            + "**doublepointer"
                            + str(marker)
                            + " = &pointer"
                            + str(marker)
                            + ";\n"
                        )
                        param += "doublepointer" + str(marker) + ", "
                        header_args += ty + "doublepointer" + str(marker) + ", "
                    else:
                        bad_fun = True
                        break
                else:
                    if ("long" in ty or "int" in ty or "short" in ty and "long double" not in ty) or (
                        "char" in ty or "string" in ty
                    ):
                        stub += (
                            "auto data" + str(marker) + "= provider.ConsumeIntegral<" + ty + ">();\n"
                        )
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    elif "float" in ty or "double" in ty:
                        stub += (
                            "auto data"
                            + str(marker)
                            + "= provider.ConsumeFloatingPoint<"
                            + ty
                            + ">();\n"
                        )
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    elif "bool" in ty:
                        stub += "auto data" + str(marker) + "= provider.ConsumeBool();\n"
                        param += "data" + str(marker) + ", "
                        header_args += ty + " data" + str(marker) + ", "
                    else:
                        bad_fun = True
                        break
                marker += 1
            if bad_fun:
                bad_fun_count += 1
                continue
            else:
                good_fun_count += 1
            param = fun_signature_to_params(param)
            header_args = fun_signature_to_params(header_args)
            if int(args.detection) == 0:
                main_section = (
                    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t'
                    + stub
                    + str(shared_functions["function"][index3])
                    + "("
                    + param
                    + ");\nreturn 0;\n}"
                )
            else:  # args.detection == 1
                # print("We are here!@#")
                # print(str(shared_functions["function"][index3]))
                # print(str(shared_functions["type_or_loc"][index3]))
                # print(header_args)
                main_section = (
                    str(shared_functions["type_or_loc"][index3])
                    + " "
                    + str(shared_functions["function"][index3])
                    + "("
                    + header_args
                    + ');\n\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t'
                    + stub
                    + str(shared_functions["function"][index3])
                    + "("
                    + param
                    + ");\nreturn 0;\n}"
                )
            full_source = header_section + main_section
            filename = "".join(
                [
                    c
                    for c in str(shared_functions["function"][index3])
                    if c.isalpha() or c.isdigit() or c == " "
                ]
            ).rstrip()
            f = open(args.output + filename + ".cc", "w")
            f.write(full_source)
            f.close()
        library_name = str((shared_functions["object"][index3])) 
        headers_dir = os.path.dirname(shared_functions["type_or_loc"][index3])
        compile_command = cb.clangpp_command(args, filename, library_name, headers_dir)
        print(compile_command)
        subprocess.Popen(
            compile_command,
            env=env,
            shell=True,
            # stdout = compile_stdout
            stderr = compile_stderr
        )
    print("Tried creating harnesses for " + str(good_fun_count) + " out of " + str(good_fun_count + bad_fun_count) + " functions. Remainder had bad parameters (such as void *).")
    # Stuff below is for elf_functions, i.e. functions that were created using lief for lack of a .so library.
    if int(args.detection) == 1:
        for index4 in range(len(elf_functions["function"])):
            if not SKIP_CODEGEN:
                header_section = ""
                if not args.headers:
                    header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                else:
                    header_list = args.headers.split(",")
                    header_section += "#include <fuzzer/FuzzedDataProvider.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                    for x in header_list:
                        header_section += '#include "' + x + '"\n'
                stub = ""
                marker = 1
                param = ""
                header_args = ""
                for param_type in literal_eval(elf_functions["param_type"][index4]):
                    if param_type.count("*") == 1:
                        if (
                            "long" in param_type or "int" in param_type or "short" in param_type and "long double" not in param_type
                        ) or ("char" in param_type or "string" in param_type):
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeIntegral<"
                                + param_type.replace("*", "")
                                + ">();\n"
                                + param_type.replace("*", "")
                                + "*pointer"
                                + str(marker)
                                + " = &data"
                                + str(marker)
                                + ";\n"
                            )
                            param += "pointer" + str(marker) + ", "
                            header_args += param_type + "pointer" + str(marker) + ", "
                        elif "float" in param_type or "double" in param_type:
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeFloatingPoint<"
                                + param_type.replace("*", "")
                                + ">();\n"
                                + param_type.replace("*", "")
                                + "*pointer"
                                + str(marker)
                                + " = &data"
                                + str(marker)
                                + ";\n"
                            )
                            param += "pointer" + str(marker) + ", "
                            header_args += param_type + "pointer" + str(marker) + ", "
                        elif "bool" in param_type:
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeBool();\n"
                                + param_type
                                + "pointer"
                                + str(marker)
                                + " = &data"
                                + str(marker)
                                + ";\n"
                            )
                            param += "pointer" + str(marker) + ", "
                            header_args += param_type + "pointer" + str(marker) + ", "
                        else:
                            continue
                    elif param_type.count("*") == 2:
                        if (
                            "long" in param_type or "int" in param_type or "short" in param_type and "long double" not in param_type
                        ) or ("char" in param_type or "string" in param_type):
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeIntegral<"
                                + param_type.replace("*", "")
                                + ">();\n"
                                + param_type.replace("*", "")
                                + "*pointer"
                                + str(marker)
                                + " = &data"
                                + str(marker)
                                + ";\n"
                                + param_type.replace("*", "")
                                + "**doublepointer"
                                + str(marker)
                                + " = &pointer"
                                + str(marker)
                                + ";\n"
                            )
                            param += "doublepointer" + str(marker) + ", "
                            header_args += param_type + "doublepointer" + str(marker) + ", "
                        elif "float" in param_type or "double" in param_type:
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeFloatingPoint<"
                                + param_type.replace("*", "")
                                + ">();\n"
                                + param_type.replace("*", "")
                                + "*pointer"
                                + str(marker)
                                + " = &data"
                                + str(marker)
                                + ";\n"
                                + param_type.replace("*", "")
                                + "**doublepointer"
                                + str(marker)
                                + " = &pointer"
                                + str(marker)
                                + ";\n"
                            )
                            param += "doublepointer" + str(marker) + ", "
                            header_args += param_type + "doublepointer" + str(marker) + ", "
                        elif "bool" in param_type:
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeBool();\n"
                                + param_type.replace("*", "")
                                + "*pointer"
                                + str(marker)
                                + " = &data"
                                + str(marker)
                                + ";\n"
                                + param_type.replace("*", "")
                                + "**doublepointer"
                                + str(marker)
                                + " = &pointer"
                                + str(marker)
                                + ";\n"
                            )
                            param += "doublepointer" + str(marker) + ", "
                            header_args += param_type + "doublepointer" + str(marker) + ", "
                        else:
                            continue
                    else:
                        if (
                            "long" in param_type or "int" in param_type or "short" in param_type and "long double" not in param_type
                        ) or ("char" in param_type or "string" in param_type):
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeIntegral<"
                                + param_type
                                + ">();\n"
                            )
                            param += "data" + str(marker) + ", "
                            header_args += param_type + " data" + str(marker) + ", "
                        elif "float" in param_type or "double" in param_type:
                            stub += (
                                "auto data"
                                + str(marker)
                                + "= provider.ConsumeFloatingPoint<"
                                + param_type
                                + ">();\n"
                            )
                            param += "data" + str(marker) + ", "
                            header_args += param_type + " data" + str(marker) + ", "
                        elif "bool" in param_type:
                            stub += "auto data" + str(marker) + "= provider.ConsumeBool();\n"
                            param += "data" + str(marker) + ", "
                            header_args += param_type + " data" + str(marker) + ", "
                        else:
                            continue
                    marker += 1
                param = fun_signature_to_params(param)
                header_args = fun_signature_to_params(header_args)
                main_section = (
                    "#include <stdlib.h>\n#include <dlfcn.h>\n\nvoid* library=NULL;\ntypedef "
                    + str(elf_functions["e_or_loc"][index4])
                    + "(*"
                    + str(elf_functions["function"][index4])
                    + "_t)("
                    + header_args
                    + ');\nvoid CloseLibrary()\n{\nif(library){\n\tdlclose(library);\n\tlibrary=NULL;\n}\n}\nint LoadLibrary(){\n\tlibrary = dlopen("'
                    + args.library_dir
                    + str(elf_functions["object"][index4])
                    + '",RTLD_LAZY);\n\tatexit(CloseLibrary);\n\treturn library != NULL;\n}\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tFuzzedDataProvider provider(data, size);\n\t\n\tLoadLibrary();\n\t'
                    + stub
                    + str(elf_functions["function"][index4])
                    + "_t "
                    + str(elf_functions["function"][index4])
                    + "_s = ("
                    + str(elf_functions["function"][index4])
                    + '_t)dlsym(library,"'
                    + str(elf_functions["function"][index4])
                    + '");\n\t'
                    + str(elf_functions["function"][index4])
                    + "_s("
                    + param
                    + ");\n\treturn 0;\n}"
                )
                full_source = header_section + main_section
                filename = "".join(
                    [
                        c
                        for c in str(elf_functions["function"][index4])
                        if c.isalpha() or c.isdigit() or c == " "
                    ]
                ).rstrip()
                f = open(args.output + filename + ".cc", "w")
                f.write(full_source)
            compile_command = cb.clangpp_command(args, filename)
            print(compile_command)
            subprocess.Popen(
                compile_command,
                env=env,
                shell=True,
                stdout = compile_stdout,
                stderr = compile_stderr
            )
else:
    print("Invalid Mode")
