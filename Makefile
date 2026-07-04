BINARY := bitrot-md5
PREFIX ?= /usr/local

.PHONY: build test install clean lint

build:
	go build -o $(BINARY) .

test:
	go test -v

lint:
	golangci-lint run

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	gzip -c $(BINARY).1 > $(DESTDIR)$(PREFIX)/share/man/man1/$(BINARY).1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/$(BINARY).1.gz

clean:
	rm -f $(BINARY) *.md5
