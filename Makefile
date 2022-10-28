OUTDIR = ./bin
SRCDIR = ./src
OBJDIR = ./obj
CC = gcc
CFLAGS = -Wall -Werror -D_FORTIFY_SOURCE=2 -s

all: icmp-c2 icmp-implant

icmp-c2: obj/icmp-c2.o obj/c2.o
	$(CC) $(CFLAGS) -static $(OBJDIR)/icmp-c2.o $(OBJDIR)/c2.o -o $(OUTDIR)/icmp-c2
	# upx $(OUTDIR)/icmp-implant
	sudo setcap cap_net_raw=ep $(OUTDIR)/icmp-c2

icmp-implant: obj/icmp-implant.o obj/implant.o
	$(CC) $(CFLAGS) -static $(OBJDIR)/icmp-implant.o  $(OBJDIR)/implant.o -o $(OUTDIR)/icmp-implant
	# upx $(OUTDIR)/icmp-implant
	sudo setcap cap_net_raw=ep $(OUTDIR)/icmp-implant

obj/icmp-implant.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/icmp-implant.c -o $(OBJDIR)/icmp-implant.o

obj/implant.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/implant.c -o $(OBJDIR)/implant.o
	
obj/icmp-c2.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/icmp-c2.c -o $(OBJDIR)/icmp-c2.o

obj/c2.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/c2.c -o $(OBJDIR)/c2.o

clean:
	rm -f $(OBJDIR)/* $(OUTDIR)/*
