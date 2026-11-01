CFLAGS = -O2 -Wall

ingest: ingest.c
	cc $(CFLAGS) ingest.c -lpcap -o ingest

clean:
	rm -f ingest

.PHONY: clean
