all: rx tx



rx: rx.c
	gcc  -Wall radiotap.c rx.c -o rx -lpcap


tx: tx.c
	gcc -Wall tx.c -o tx -lpcap


clean:
	rm -f rx tx *~

