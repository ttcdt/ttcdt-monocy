PREFIX=/usr/local

ttcdt-monocy: ttcdt-monocy.c monocypher.o
	$(CC) -g -Wall $< monocypher.o -o $@

monocypher.o: monocypher.c monocypher.h
	$(CC) -g -Wall -Wextra -O3 -march=native -c $<

install:
	install -m 755 ttcdt-monocy $(PREFIX)/bin/ttcdt-monocy

uninstall:
	rm -f $(PREFIX)/bin/ttcdt-monocy

dist: clean
	cd .. && tar czvf ttcdt-monocy/ttcdt-monocy.tar.gz ttcdt-monocy/*

clean:
	rm -f *.o ttcdt-monocy *.tar.gz *.asc
