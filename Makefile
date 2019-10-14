CFLAGS=-g -I/usr/local/include
LDFLAGS=-L/usr/local/lib -Wl,-z,wxneeded
LIBS=-lunicorn -lcapstone -pthread

.PHONY: clean run

emulate: emulate.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

exploit: exploit.c
	$(CC) -I/usr/local/include/libusb-1.0 -o $@ $< -L/usr/local/lib -lusb-1.0

clean:
	-rm -f emulate

run: emulate
	./emulate ./sm-g960f/sboot_bl2.bin ./sm-g960f/filesystem/
