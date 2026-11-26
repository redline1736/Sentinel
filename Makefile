CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2 -D_GNU_SOURCE -pthread \
           -Wno-unused-result -Wunused-function -MMD -MP

# SDL3 + SDL3_ttf via pkg-config (falls back to nothing so the build
# still fails loudly if SDL3 isn't installed, rather than silently)
SDL3_CFLAGS := $(shell pkg-config --cflags sdl3 sdl3-ttf 2>/dev/null)
SDL3_LIBS   := $(shell pkg-config --libs   sdl3 sdl3-ttf 2>/dev/null)

CFLAGS  += $(SDL3_CFLAGS)
LIBS    := $(SDL3_LIBS) -lcurl -lpthread -lcjson -lm

SRCS = src/main.c \
       src/gui/ui.c \
       src/util/util.c \
       src/prox/prox.c \
       src/scan/scan.c \
       src/http/http.c \
       src/recon/info.c \
       src/chrome/chrome.c \
       src/deepblue/deepblue.c \
       src/atlas/sub.c \
       src/headers/hdr.c \
       src/glassworm/gw.c src/glassworm/csrf/csrf.c src/glassworm/xxe/xxe.c \
       src/ghostquery/gq.c src/ghostquery/sql/sql.c src/ghostquery/xss/xss.c src/ghostquery/openredirect/oprt.c

OBJS = $(SRCS:.c=.o)
BIN  := sentinel

.PHONY: all clean sanitize

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -I. $(OBJS) -o $@ $(LIBS)

sanitize: CFLAGS += -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LIBS   += -fsanitize=address,undefined
sanitize: $(BIN)

clean:
	rm -f $(BIN) $(OBJS) $(OBJS:.o=.d)

-include $(OBJS:.o=.d)