BOFNAME := adrecon
CC_x64  := x86_64-w64-mingw32-gcc
CC_x86  := i686-w64-mingw32-gcc

# BOF-safe flags: no stack protector / chkstk / unwind (those symbols are
# unresolved inside Beacon and crash the implant).
CFLAGS := -Os -DBOF -fno-asynchronous-unwind-tables -fno-ident \
          -fno-stack-protector -fno-exceptions -mno-stack-arg-probe

all:
	@mkdir -p $(BOFNAME)
	$(CC_x64) -o $(BOFNAME)/$(BOFNAME).x64.o $(CFLAGS) -c $(BOFNAME).c
	$(CC_x86) -o $(BOFNAME)/$(BOFNAME).x86.o $(CFLAGS) -c $(BOFNAME).c
	@echo "[+] Build complete: $(BOFNAME)/$(BOFNAME).x64.o and $(BOFNAME)/$(BOFNAME).x86.o"

clean:
	rm -f $(BOFNAME)/$(BOFNAME).*.o
	rm -rf $(BOFNAME)
	@echo "[+] Clean complete"
