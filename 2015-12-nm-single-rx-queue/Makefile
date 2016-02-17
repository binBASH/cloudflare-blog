CC=gcc
CFLAGS=-Wall -I deps/netmap/sys/ -I /usr/local/include/luajit-2.0 -O2 -lluajit-5.1
LDFLAGS=-L /usr/local/lib
SOURCES=main.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=nm-single-rx-queue

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ -lluajit-5.1

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	@rm $(OBJECTS) $(EXECUTABLE)
