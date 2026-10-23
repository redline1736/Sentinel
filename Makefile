CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2 -D_GNU_SOURCE -pthread \
           -Wno-unused-result -Wno-unused-function

# No source uses SDL — removed. pkg-config was also expanded as a make
# variable (silently empty); fixed by removing it entirely.
LIBS    := -lcurl -lpthread -lcjson -lm

SRCS = src/main.c src/util/util.c src/prox/prox.c src/scan/scan.c src/chrome/chrome.c src/http/http.c\
       src/deepblue/deepblue.c \
       src/atlas/sub.c \
       src/glassworm/gw.c src/glassworm/ src/glassworm/csrf/csrf.c \
       src/ghostquery/gq.c  src/ghostquery/sql/sql.c src/ghostquery/xss/xss.c src/ghostquery/openredirect/oprt.c

HDRS := $(wildcard src/*.h src/*/*.h)
BIN  := sentinel

.PHONY: all clean sanitize

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -I. $(SRCS) -o $@ $(LIBS)

sanitize: CFLAGS += -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LIBS += -fsanitize=address,undefined
sanitize: $(BIN)

clean:
	rm -f $(BIN)