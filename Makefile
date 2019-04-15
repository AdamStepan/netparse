LDFLAGS := $(LDFLAGS) -lpcap

netparse: netparse.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	$(RM) netparse
