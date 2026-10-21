CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lsqlite3

SRCS = server.c decode.c \
       wire/fields.c wire/checksum.c \
       refdata/refdata.c \
       compliance/decision.c \
       serialize/json.c

rpt7_server: $(SRCS)
	$(CC) $(CFLAGS) -o rpt7_server $(SRCS) $(LDFLAGS)

clean:
	rm -f rpt7_server
