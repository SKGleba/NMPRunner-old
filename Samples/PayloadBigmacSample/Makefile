PREFIX=mep-elf-
CC=$(PREFIX)gcc
CFLAGS=-fno-delete-null-pointer-checks -nostdlib -fno-optimize-sibling-calls -mc=tiny -Os -std=gnu99 -mel
LOADER_CFLAGS=-nostdlib -mc=far -mtf -ml -Os -std=gnu99 -mel
LD=$(PREFIX)gcc
LDFLAGS= -nodefaultlibs -nostdlib
OBJCOPY=$(PREFIX)objcopy
OBJCOPYFLAGS=

OBJ=main.o

all: payload.bin

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.ao: %.S
	$(CC) -c -o $@ $< $(CFLAGS)

payload.elf: $(OBJ)
	$(LD) -o $@ $^ $(LDFLAGS)

%.h: %.bin
	xxd -i $< > $@

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
