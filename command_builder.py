#!/usr/bin/env python3

import os


def cp_onearglocation_to_ql(args):
    return "cp " + os.getcwd() + "/onearglocation.ql "


def one_arg(args):
    command = (
        "cd "
        + args.ql
        + ";"
        + args.ql
        + "codeql query run onearglocation.ql -o "
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
        + "onearg.csv"
    )
    return command


def clang_command(args, filename, library_name=None, headers_dir=None):
    command = "clang -g -fsanitize=address,undefined,fuzzer "
    if args.flags:
        command += args.flags
        command += " -L " + args.output + " -L " + args.library_dir
    if int(args.detection) == 0:
        command += " -I" + headers_dir
    if library_name is None:
        print("Error: bug where no library_name is passed to clang_command!")
        exit(1)
    command += (
        " -l:" + library_name + " " + args.output + filename + ".c -o " + args.output + filename
    )
    return command


def clang_command_2(args, filename):
    command = "clang -g -fsanitize=address,undefined,fuzzer "
    if args.flags:
        command += args.flags
    command += " " + args.output + filename + ".c -o " + args.output + filename
    return command


def clangpp_command(args, filename, library_name=None, headers_dir=None):
    command = "clang++ -g -fsanitize=address,undefined,fuzzer "
    if args.flags is not None:
        command += args.flags + " "
    # command += args.output
    # Check consistency of library-arguments
    if (args.library_dir is not None and library_name is None) or (
        args.library_dir is None and library_name is not None
    ):
        print(
            "Error: args.library_dir is "
            + args.library_dir
            + ", library_name is "
            + library_name
            + ". Either both or none should be None."
        )
        exit(1)
    # Add library arguments to command
    elif args.library_dir is not None:
        command += " -L " + args.library_dir
    if int(args.detection) == 0:
        command += " -I" + headers_dir
    if args.library_dir is not None:
        command += " -l:" + library_name + " " + args.output
    command += filename + ".cc -o " + args.output + filename
    return command
