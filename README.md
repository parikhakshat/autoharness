# AutoHarness
##### Created by Akshat Parikh
***
## What is this tool?
AutoHarness is a tool that automatically generates fuzzing harnesses for you. This idea stems from a concurrent problem in fuzzing codebases today: large codebases have thousands of functions and pieces of code that can be embedded fairly deep into the library. It is very hard or sometimes even impossible for smart fuzzers to reach that codepath. 
Even for large fuzzing projects such as oss-fuzz, there are still parts of the codebase that are not covered in fuzzing. Hence, this program tries to alleviate this problem in some capacity as well as provide a tool that security researchers can use to initially test a code base. This program only supports code bases which are coded in C and C++. 
## Setup/Demonstration
This program utilizes llvm and clang for libfuzzer, Codeql for finding functions, and python for the general program. This program was tested on Ubuntu 20.04 with llvm 12 and python 3. Here is the initial setup.
```bash
sudo apt-get update;
sudo apt-get install python3 python3-pip llvm-12* clang-12 git;
pip3 install pandas lief subprocess os argparse ast;
```
Follow the installation procedure for Codeql on https://github.com/github/codeql.
Make sure to install the CLI tools and the libraries. For my testing, I have stored both the tools and libraries under one folder.
Finally, clone this repository or download a release.
Here is the program's output after running on nginx with the multiple argument mode set. 
This is the command I used. 
```bash
python3 harness.py -L /home/akshat/nginx-1.21.0/objs/ -C /home/akshat/codeql-h/ -M 1 -O /home/akshat/autoharness/ -D nginx -G 1 -Y 1 -F "-I /home/akshat/nginx-1.21.0/objs -I /home/akshat/nginx-1.21.0/src/core -I /home/akshat/nginx-1.21.0/src/event -I /home/akshat/nginx-1.21.0/src/http -I /home/akshat/nginx-1.21.0/src/mail -I /home/akshat/nginx-1.21.0/src/misc -I /home/akshat/nginx-1.21.0/src/os -I /home/akshat/nginx-1.21.0/src/stream -I /home/akshat/nginx-1.21.0/src/os/unix" -X ngx_config.h,ngx_core.h
```
Results:
![image](https://user-images.githubusercontent.com/68412398/125177087-f317e580-e18d-11eb-8497-02ac3dfc67f9.png)
It is definitely possible to raise the success by further debugging the compilation and adding more header files and more. Note the nginx project does not have any shared objects after compiling. However, this program does have a feature that can convert PIE executables into shared libraries. 
## Planned Features (in order of progress)
1. ### Struct Fuzzing
The current way implemented in the program to fuzz functions with multiple arguments is by using fuzzing data provider. There are some improvements to make in this integration; however, I believe I can incorporate this feature with data structures. A problem which I come across when coding this is with codeql and nested structs. It becomes especially hard without writing multiple queries which vary for every function. In short, this feature needs more work. I was also thinking about a simple solution using protobufs.

2. ### Implementation Based Harness Creation
Using codeql, it is possible to use to generate a control flow graph that maps how the parameters in a function are initialized. Using that information, we can create a better harness. Another way is to look for implementations for the function that exist in the library and use that information to make an educated guess on an implementation of the function as a harness. The problems I currently have with this are generating the control flow graphs with codeql.

3. ### Parallelized fuzzing/False Positive Detection
I can create a simple program that runs all the harnesses and picks up on any of the common false positives using ASAN. Also, I can create a new interface that runs all the harnesses at once and displays their statistics.
## Contribution/Bugs
If you find any bugs with this program, please create an issue. I will try to come up with a fix. Also, if you have any ideas on any new features or how to implement performance upgrades or the current planned features, please create a pull request or an issue with the tag (contribution).
## PSA
This tool generates some false positives. Please first analyze the crashes and see if it is valid bug or if it is just an implementation bug. Also, you can enable the debug mode if some functions are not compiling. This will help you understand if there are some header files that you are missing or any linkage issues. If the project you are working on does not have shared libraries but an executable, make sure to compile the executable in PIE form so that this program can convert it into a shared library.
## References
1. https://lief.quarkslab.com/doc/latest/tutorials/08_elf_bin2lib.html
