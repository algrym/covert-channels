#
# Covert Channel
#
# A. J. Wright - <ajw@utk.edu>
#
# $Id: Makefile,v 1.14 2006/08/04 19:57:33 ajw Exp $
#

TARGETS = csrc cdst

all: $(TARGETS)

# encoding type, must be "1" or "2" (no quotes)
ENCODING=1
ENCODING=2

LIBPCAPBASE=/usr/local/libpcap
LIBDNETBASE=/usr/local/libdnet
LIBFDRBASE=/usr/local/libfdr

CC = gcc

INCLUDES=-I$(LIBDNETBASE)/include -I$(LIBPCAPBASE)/include -I$(LIBFDRBASE)
LIBDIRS=-L$(LIBDNETBASE)/lib -L$(LIBPCAPBASE)/lib -L$(LIBFDRBASE)
LIBS=-lpcap $(LIBDNETBASE)/lib/libdnet.a
DEFS=-D_BSD_SOURCE

CFLAGS = -O -g $(DEFS) -Wall -pedantic -O $(INCLUDES)
LDFLAGS = -O -g $(DEFS) -Wall -pedantic -O

OBJS = pktRecv.o pktXmit.o util.o codec.o

csrc.o: csrc.c csrc.h

cdst.o: cdst.c cdst.h

csrc: csrc.o $(OBJS)
	$(CC) -o $(@) $(LIBDIRS) $(@).o $(OBJS) $(LIBS)

cdst: cdst.o $(OBJS)
	$(CC) -o $(@) $(LIBDIRS) $(@).o $(OBJS) $(LIBS)

clean:
	rm -fr $(OBJS) $(TARGETS) *~ *.out *.o

rsync:
	make clean
	rsync -avlC --delete --progress -e ssh `pwd` ajw@andromeda.iso.utk.edu:work/covert/

.SUFFIXES: .c .o
.c.o: $*.c $*.h
	$(CC) $(CFLAGS) -DENCODING=$(ENCODING) -c $(*).c
