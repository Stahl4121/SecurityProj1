all: alice bob

alice: main.o ab_common.o
	gcc main.o ab_common.o -lcrypto -o alice

bob: main.o ab_common.o
	gcc main.o ab_common.o -lcrypto -o bob

main.o: main.c
	gcc -g -c main.c -o main.o

ab_common.o: ab_common.c
	gcc -g -c ab_common.c -o ab_common.o

clean:
	rm -rf alice bob *.o
