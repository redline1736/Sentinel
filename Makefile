CC      ?= gcc
# Removed -Werror, added warning suppressions
CFLAGS  += -Wall -Wextra -O2 -D_GNU_SOURCE -pthread \
           -Wno-unused-result -Wno-unused-function \
           -Wno-format-truncation -Wno-sign-compare
LIBS    := -lcurl -lpthread -lcjson

SRCS = src/main.c src/util/util.c src/prox/prox.c src/scan/scan.c \
       src/deepblue/deepblue.c src/ghostquery/gq.c src/chrome/chrome.c \
       src/glassworm/gw.c src/glassworm/graphql/graphql.c src/glassworm/http/http.c src/glassworm/sock/sock.c \
       
		
HDRS := $(wildcard src/*.h src/*/*.h)
BIN  := sentinel

.PHONY: all clean sanitize

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -I. $(SRCS) -o $@ $(LIBS)

# build with Address/UB sanitizers for local dev
sanitize: CFLAGS += -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LIBS += -fsanitize=address,undefined
sanitize: $(BIN)

clean:
	rm -f $(BIN)