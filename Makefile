bloomindex:	bloomindex.o crc32.o murmur32.o
	gcc -ggdb -o bloomindex bloomindex.o crc32.o murmur32.o -lm
bloomindex.o:	bloomindex.c
	#gcc -DDATA_DEBUG -DDEBUG -ggdb -Wall -c bloomindex.c
	gcc  -ggdb -Wall -c bloomindex.c

crc32.o:	crc32.c
	gcc -Wall -ggdb -c crc32.c
murmur32.o:	murmur32.c
	gcc -Wall -ggdb -c murmur32.c
