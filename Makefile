
LDFLAGS=-lpcap
CPPFLAGS=-Wall

all: rx tx txhook.so txhookpipe rxll




txhook.so: txhook.c
	gcc $(CPPFLAGS) -fPIC -shared -o $@ $<

txhookpipe: txhookpipe.o
	gcc -o $@ $^ $(LDFLAGS )

rxll: rxll.o lib.o radiotap.o
	gcc -g3 -o $@ $^ $(LDFLAGS)

%.o: %.c
	gcc -g3 -c -o $@ $< $(CPPFLAGS)


rx: rx.o lib.o radiotap.o fec.o
	gcc -o $@ $^ $(LDFLAGS)


tx: tx.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)


clean:
	rm -f rx tx *~ *.o *.so

