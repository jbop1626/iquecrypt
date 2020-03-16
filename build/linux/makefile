PROG    = iquecrypt

OUTDIR  = ../../bin/linux/
OBJDIR  = $(OUTDIR)obj/
SRCDIR  = ../../src/

CC      = gcc
CFLAGS  = -O3 -Wall -Wextra -pedantic
OBJ     = $(OBJDIR)main.o $(OBJDIR)io.o $(OBJDIR)crypt.o $(OBJDIR)extract.o $(OBJDIR)ecdh.o $(OBJDIR)ecc.o $(OBJDIR)aes.o  
LDFLAGS =
LDLIBS  = 


$(PROG): $(OBJ)
	$(CC) -o $(OUTDIR)$@ $^ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

$(OBJDIR)%.o:
	@mkdir -p $(OBJDIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJDIR)main.o:    $(SRCDIR)main.c $(SRCDIR)io.h $(SRCDIR)crypt.h $(SRCDIR)extract.h $(SRCDIR)ecdh.h
$(OBJDIR)io.o:      $(SRCDIR)io.c $(SRCDIR)io.h
$(OBJDIR)crypt.o:   $(SRCDIR)crypt.c $(SRCDIR)crypt.h $(SRCDIR)io.h $(SRCDIR)aes/aes.h
$(OBJDIR)extract.o: $(SRCDIR)extract.c $(SRCDIR)extract.h $(SRCDIR)io.h
$(OBJDIR)ecdh.o:    $(SRCDIR)ecdh.c $(SRCDIR)ecdh.h $(SRCDIR)io.h $(SRCDIR)ecc/ecc.h
$(OBJDIR)ecc.o:     $(SRCDIR)ecc/ecc.c $(SRCDIR)ecc/ecc.h
$(OBJDIR)aes.o:     $(SRCDIR)aes/aes.c $(SRCDIR)aes/aes.h

.PHONY: clean
clean:
	rm -f $(OUTDIR)$(PROG) $(OBJDIR)*.o 

.PHONY: install
install:
	install $(OUTDIR)$(PROG) /usr/local/bin/

.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(PROG)

