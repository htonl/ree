#change compiler here if needed
CC=gcc

all:
	$(CC) instruction.c tree.c hash.c list.c ree.c -o ree

debug:
	$(CC) -g -DDEBUG instruction.c tree.c list.c hash.c ree.c -o ree_debug

clean:
	rm ree ree_debug
