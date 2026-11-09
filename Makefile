CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2 -D_GNU_SOURCE -pthread \
           -Wno-unused-result -Wno-unused-function -MMD -MP

LIBS    := -lcurl -lpthread -lcjson -lm

SRCS = src/main.c \
       src/util/util.c \
       src/prox/prox.c \
       src/scan/scan.c \
       src/http/http.c \
       src/recon/info.c \
       src/chrome/chrome.c \
       src/deepblue/deepblue.c \
       src/atlas/sub.c \
       src/headers/hdr.c \
       src/glassworm/gw.c src/glassworm/csrf/csrf.c \
       src/ghostquery/gq.c src/ghostquery/sql/sql.c \
       src/ghostquery/xss/xss.c src/ghostquery/openredirect/oprt.c

OBJS = $(SRCS:.c=.o)
BIN  := sentinel

.PHONY: all clean sanitize

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -I. $(OBJS) -o $@ $(LIBS)

sanitize: CFLAGS += -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize: LIBS += -fsanitize=address,undefined
sanitize: $(BIN)

clean:
	rm -f $(BIN) $(OBJS) $(OBJS:.o=.d)

-include $(OBJS:.o=.d)