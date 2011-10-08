LIBS=-lgpgme
EXTRA_CFLAGS=-ggdb

all:
	gcc ${EXTRA_CFLAGS} ${LIBS} -o fishbowl fishbowl.c

clean:
	rm -f fishbowl core a.out *.o TEST_OUT/*
