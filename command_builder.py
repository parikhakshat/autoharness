#!/usr/bin/env python3

import os


def cp_onearglocation_to_ql(args):
    return "cp " + os.getcwd() + "/onearglocation.ql "


def one_arg(args):
    command = \
    "cd " \
    +args.ql \
    +";" \
    +args.ql \
    +"codeql query run onearglocation.ql -o " \
    +args.output \
    +"onearg.bqrs -d " \
    +args.ql \
    +args.database \
    +";" \
    +args.ql \
    +"codeql bqrs decode --format=csv " \
    +args.output \
    +"onearg.bqrs -o " \
    +args.output \
    +"onearg.csv"
    return command

def compile_command(args, filename):
    command = "clang++ -g -fsanitize=address,undefined,fuzzer "
    if args.flags is not None:
        command += args.flags + " "
    command += args.output \
            + filename \
            + ".cc -o " \
            + args.output \
            + filename
    return command