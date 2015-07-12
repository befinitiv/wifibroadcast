
LDFLAGS=-lpcap
CPPFLAGS=-Wall

all: rx tx



%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)


rx: rx.o lib.o radiotap.o fec.o
	gcc -o $@ $^ $(LDFLAGS)


tx: tx.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)


clean:
	rm -f rx tx *~ *.o

