all: rx tx



rx: rx.c lib.c
	gcc  -Wall radiotap.c rx.c lib.c -o rx -lpcap


tx: tx.c lib.c
	gcc -Wall tx.c lib.c -o tx -lpcap


clean:
	rm -f rx tx *~

