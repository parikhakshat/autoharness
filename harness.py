import os
import argparse
import subprocess
import time
import csv
import glob, os
import pandas as pd
import numpy
parser = argparse.ArgumentParser(description='AutoHarness')
parser.add_argument('-L', '--library', help = "Specify directory to program's libraries", required=True)
parser.add_argument('-C', '--ql', help = "Specify directory of codeql modules, database, and binary", required=True)
parser.add_argument('-D', '--database', help = "Specify Codeql database", required=True)
parser.add_argument('-M', '--mode', help = "Specify 0 for 1 argument harnesses or 1 for multiple argument harnesses", required=True)
parser.add_argument('-O', '--output', help = "Output directory", required=True)
parser.add_argument('-F', '--flags', help = "Specify compiler flags (include)", required=False)
args = parser.parse_args()
shared_objects=[]
defined_functions={"output":[],"object":[]}
total_functions={"function":[],"object":[]}
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
        defined_functions["output"].append(subprocess.run(["nm", "-D","-C",x], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        defined_functions["object"].append(x)
    df = pd.read_csv(args.output + "onearg.csv")
    foo = df[['f']].to_numpy()
    for x in foo:
        #print(str(x).translate(str.maketrans('', '', "'[]")))
        for s in range(len(defined_functions["output"])):
            if str(x).translate(str.maketrans('', '', "'[]")) in defined_functions["output"][s]:
                #print(defined_functions["object"][s])
                total_functions["function"].append(x)
                total_functions["object"].append(defined_functions["object"][s])
    functions = []
    for x in functions:
        print(x)
elif (int(args.mode) == 1):
    print("bob")
else:
    print("Invalid Mode")
    
