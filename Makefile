all:
	gcc -g instruction.c tree.c hash.c list.c ree.c -o ree

debug:
	gcc -g -DDEBUG instruction.c tree.c list.c hash.c ree.c -o ree

clean:
	rm ree
