TARGET = ftconvert
LIBS = -lwandio -lflowtuple -lcorsaro -ltrace -lJudy
CC = gcc
CFLAGS = -g -Wall -O2
LDFLAGS=

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS= $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS= $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall -o $@ $(LDFLAGS) $(LIBS)

clean:
	-rm -f *.o
	-rm -f $(TARGET)
