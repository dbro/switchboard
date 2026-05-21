BIN = switchboard

# Use cosmocc for a portable APE binary that runs on Linux/macOS/Windows/FreeBSD.
# Falls back to the system C compiler for a native build.
COSMOCC := $(shell command -v cosmocc 2>/dev/null)

ifdef COSMOCC
  CC     = cosmocc
  CFLAGS = -O2 -Wall -Wextra
  $(info Building portable APE binary with cosmocc)
else
  CC     = cc
  CFLAGS = -O2 -Wall -Wextra
  $(info cosmocc not found — building native binary)
endif

.PHONY: all clean

all: $(BIN)

$(BIN): switchboard.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN) $(BIN).exe
