# ree

Ree is the name of the program I put together for this assignment.

# Build instructions

if you have gcc installed, cd into src/ and run $make. The binary named "ree" will be compiled in
this directory.

# How to use

NOTE: instructions.txt must be in the same directory as the ./ree binary when
you are running it.

Run the binary like any other C executable: ./ree
The argument to this program is just -i "filename" where filename is the name of
the file we want to disassemble. Ex usage:

$cd src/
$./ree -i ../examples/example1.o

# Description

All source code here was written from scratch, with a little bit of help on the
hash algorithm chosen from stack overflow.

Basically, the disassembler works like this:

1) A hash table is built using the instructions.txt file
    - This file is the list of supported instructions
    - Format is opcode name, opcode bytes (comma separated), op encoding modes
      (M, RM, MR, RMI, etc.), and finally, the r prefix (if there is one).
2) The file to be disassembled is opened and a buffer reads some of the file
3) The program then processes the data in this buffer, and builds a binary tree
of the instructions. It uses the address of the instruction as the key to the
tree.
4) Once this buffer is completely read, then we read more of the file into the
re-used buffer, and continue.
5) Labels from branches are stored into a linked list. Once the tree is
completed, we loop through the list once and add labels to the instructions in
the tree that have them.
6) Finally, the instruction tree is traversed, and the instructions printed in
order

The program takes one argument, '-i' which is used to specify the input file
which we are disassembling. The output is then printed to stdinput.

If the program crashes because of OOM, then please try changing the
MAXBYTESBEFOREPRINT macro in ree.c. It is the max number of bytes we will read
before printing to the screen. These bytes on avg each take up 1 struct
instruction, and by default MAXBYTESBEFOREPRINT is 64K.

Each data structure used (list, tree, hashtable), has its own API files in src/
and then there is ree.c which contains main(), and all the parsing logic and uses the API's
defined in the other files.

# NOTES

All of the examples in the examples/ dir have been modified from their original
versions.
