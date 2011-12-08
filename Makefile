LIBS=`gpgme-config --cflags --libs`
EXTRA_CFLAGS=-ggdb

all:
	gcc ${EXTRA_CFLAGS} ${LIBS} -o fishbowl fishbowl.c

clean:
	rm -f fishbowl fishbowl*.log core a.out *.o TEST_OUT/*
