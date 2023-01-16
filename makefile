LDLIBS += -lpcap

all: beacon-flood

beacon-flood: main.o mac.o
		$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f beacon-flood *.o
