ROOT		:= $(PWD)
CC			:= gcc
RUBYINC	:= /usr/lib/ruby/1.8/i486-linux
CFLAGS	:= -DDEBUG -I $(ROOT)/include -I $(RUBYINC) -I $(ROOT)/libnids-1.23/src/ -ggdb
LDFLAGS	:= -ggdb -L$(ROOT)/libnids-1.23/src/ -lnids -lpcap -lnet -lruby1.8
PACKAGE	:= wireplay-$(shell date "+%Y%m%d").tar.gz
DEVPACKAGE	:= wireplay-dev-$(shell date "+%Y%m%d").tar.gz
SVNPATH	:= https://wireplay.googlecode.com/svn/trunk

CORE_OBJ	:= src/wireplay.o src/log.o src/msg.o src/whook.o src/whook_rb.o

all: wireplay

wireplay: $(CORE_OBJ) 
	$(CC) -o wireplay $(CORE_OBJ) $(LDFLAGS)

.PHONY: clean
clean:
	-rm -rf wireplay
	-rm -rf src/*.o
	-rm -rf core core.*
	-rm -rf a.out

.PHONY: upload
upload:
	-make clean

.PHONY: package
package:
	make clean
	rm -rf /tmp/wireplay
	svn --force export $(SVNPATH) /tmp/wireplay 
	cd /tmp/ && tar czvf $(PACKAGE) wireplay
	rm -rf /tmp/wireplay
	mv /tmp/$(PACKAGE) ./releases/

.PHONY: package-dev
package-dev:
	make clean
	rm -rf /tmp/wireplay
	svn checkout $(SVNPATH) /tmp/wireplay 
	cd /tmp/ && tar czvf $(DEVPACKAGE) wireplay
	rm -rf /tmp/wireplay
	mv /tmp/$(DEVPACKAGE) ./releases/

.PHONY: install
install:
	mkdir -p /opt/wireplay/bin
	cp wireplay /opt/wireplay/bin/
	cp -r pcap /opt/wireplay/
	cp -r hooks /opt/wireplay/
