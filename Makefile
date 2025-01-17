BOFNAME := persistask
COMINCLUDE := -I ./common
CC_x64 := x86_64-w64-mingw32-gcc


all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c persistask.c -DBOF 

clean:
	rm $(BOFNAME).*.exe
