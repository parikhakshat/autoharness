#!/usr/bin/env python3

import argparse

def create_parser():
    parser = argparse.ArgumentParser(
        description="""\
    A program to help you to automatically create fuzzing harnesses.         
    """
    )
    parser.add_argument(
        "-L", "--library-dir", help="Specify directory to program's libraries", required=True
    )
    parser.add_argument(
        "-C", "--ql", help="Specify directory of codeql modules, database, and binary", required=True
    )
    parser.add_argument("-D", "--database", help="Specify Codeql database", required=True)
    parser.add_argument(
        "-M",
        "--mode",
        help="Specify 0 for 1 argument harnesses or 1 for multiple argument harnesses",
        required=True,
    )
    parser.add_argument("-O", "--output", help="Output directory", required=True)
    parser.add_argument("-F", "--flags", help="Specify compiler flags (include)", required=False)
    parser.add_argument(
        "-X", "--headers", help="Specify header files (comma seperated)", required=False
    )
    parser.add_argument(
        "-G", "--debug", help="Specify 0/1 for disabling/enabling debug mode.", required=True
    )
    parser.add_argument(
        "-Y",
        "--detection",
        help="Automatic header detection (0) or Function Definition (1).",
        required=True,
    )
    return parser