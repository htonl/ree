all:
	gcc -g instruction.c tree.c hash.c reee.c -o ree

debug:
	gcc -g -DDEBUG instruction.c tree.c hash.c reee.c -o ree

clean:
	rm ree
