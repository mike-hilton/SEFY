TARGET:= sefy
SRC:= src/main.c
CC:= gcc
CFLAGS:= -std=c99 -O2 -fstack-protector-all -fpie -pie -fstack-protector-strong -Wall -Wextra -Wpedantic -Wnull-dereference -Wformat=2 -Wduplicated-cond -Wfloat-equal -Wformat-security -Wno-unused-parameter -Wshadow -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wredundant-decls -Wnested-externs
LIBS:= -lsodium
PREFIX:= /usr/local/bin

all:
	 $(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)

install:
	 cp ./$(TARGET) $(PREFIX)/$(TARGET)

clean:
	 rm sefy
