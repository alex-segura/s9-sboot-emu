CFLAGS=-g -I/usr/local/include -I/usr/local/include/guile/2.2
LDFLAGS=-L/usr/local/lib -Wl,-z,wxneeded
LIBS=-lunicorn -lcapstone -lguile-2.2 -lgc -pthread

.PHONY: clean run

emulate: emulate.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

exploit: exploit.c
	$(CC) -I/usr/local/include/libusb-1.0 -o $@ $< -L/usr/local/lib -lusb-1.0

clean:
	-rm -f emulate

run: emulate
	./emulate ./sm-g960f/sboot_bl2.bin
