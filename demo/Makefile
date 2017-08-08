DRV_RULES_DIR =../..

-include $(DRV_RULES_DIR)/suma_rdk_config

TARGET = sockets_demo
CROSS_COMPILE = $(COMPILE_PREFIX)
EXE_DIR = .

HEADER_DIR = $(DRV_RULES_DIR)/../../include
SOCKETS_DIR = ../
RELEASE_DIR = $(DRV_RULES_DIR)/../../release

CMAI_DIR := /opt/cmai
CMAI_LIB_DIR = $(CMAI_DIR)/lib/ti81xx
CMAI_INCLUDE = $(CMAI_DIR)/include
SUBLIB = param_mq cmai param_xml pthread_base hmi tvp5150 ipc suma_trace_log
ADD_SUBLIB_INC = $(foreach n,$(SUBLIB),-I$(CMAI_INCLUDE)/$(n))
ADD_SUBLIB = $(foreach n,$(SUBLIB),-l$(n))

LIBS =   $(SOCKETS_DIR)libnet_sockets.a

CFLAGS = -I$(HEADER_DIR) -I$(SOCKETS_DIR) -Wall -g
#CFLAGS += $(ADD_SUBLIB_INC)

LDFLAGS = -lpthread -L$(RELEASE_DIR) -L$(SOCKETS_DIR) -lnet_sockets
#LDFLAGS += -L$(CMAI_LIB_DIR) $(ADD_SUBLIB)

EXTRA_CFLAGS =	-I$(DRV_RULES_DIR)/../include -I$(COMPILE_INCLUDE)

objects := $(patsubst %.c,%.o,$(wildcard *.c))
executables := $(patsubst %.c,%,$(wildcard *.c))

all : TARGET 

TARGET : $(objects)
	$(CROSS_COMPILE)gcc $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) -o $(TARGET) $(objects) $(LIBS)
	
$(objects): %.o: %.c
	$(CROSS_COMPILE)gcc  -c $(CFLAGS) $< -o $@

install:
	install -d $(EXEC_DIR)
	install $(executables) $(EXEC_DIR)

clean:
	rm -f $(EXE_DIR)/$(executables) 
	rm -f *.o
	@for DIR in $(executables); do \
		rm -f $(EXE_DIR)/$$DIR; \
	done

distclean: clean
	rm -f *.o

splint:
	splint +posixlib -retvalint +I$(COMPILE_INCLUDE)  *.c
