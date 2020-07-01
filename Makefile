CC = gcc

CFLAGS = -Wall -ggdb -std=c99 -lssl -lcrypto

DEPS = KeyExp.h aesC.h CBCpkcs.h md5sum.h

OBJ = KeyExp.o AES.o aesC.o CBCpkcs.o md5sum.o

%.o : %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

AES : $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY : clean

clean:
	-rm -f $(OBJ)
	-rm -f 
