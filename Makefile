all:
	gcc -g instruction.c tree.c hash.c reee.c -o ree

test:
	gcc -g instruction.c tree.c hash.c test.c -o test

clean:
	rm test
