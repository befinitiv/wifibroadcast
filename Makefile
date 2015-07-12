all: rx tx



rx: rx.c lib.c
	gcc -g3 -Wall radiotap.c fec.c rx.c lib.c -o rx -lpcap


tx: tx.c lib.c
	gcc -g3 -Wall fec.c tx.c lib.c -o tx -lpcap


clean:
	rm -f rx tx *~

