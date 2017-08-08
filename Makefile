DRV_RULES_DIR =..
EVM_DEMOAPP_DIR = .
#include $(EVM_DEMOAPP_DIR)/../Rules.make
include $(DRV_RULES_DIR)/suma_rdk_config 
include ../cmai_inc
NAME = net_sockets
LIB_NAME = lib$(NAME).a
RELEASE_DIR = ../../../release
HEADER_DIR = ../../../include
OSA_INC = ../suma_osa/


# archiver and its options
ARFLAGS = -r

#CFLAGS = 
CROSS_COMPILE = $(COMPILE_PREFIX)
EXE_DIR = .

ifeq ($(BUILD_TYPE), release)
    CFLAGS		+= -DNDEBUG
    CFLAGS		+= -O2
else
    CFLAGS		=
    CFLAGS		+= -g
endif



LDFLAGS = -lpthread
#EXTRA_CFLAGS =	-I$(DRV_RULES_DIR)/../../common
HEADERS = $(wildcard *.h)

objects := $(patsubst %.c,%.o,$(wildcard *.c))
executables := $(patsubst %.c,%,$(wildcard *.c))

LINTFLAGS := +posixlib -linelen 160 
LINTFLAGS += -exportlocal 	# 函数未 被本模块之外引用
LINTFLAGS += -likelybool	# boolean bool int等类型
LINTFLAGS += -nullpass 		# pthread_mutex_t函数：参数含NULL

INCDIRS := -I. -I$(COMPILE_INCLUDE) -I$(OSA_INC) -I$(HEADER_DIR) 
INCDIRS += $(ADD_SUBLIB_INC)
CFLAGS += -shared $(INCDIRS) -Wall #-Werror

all: LIB_NAME
LIB_NAME : $(objects)
	$(AR) $(ARFLAGS) $(LIB_NAME) $(objects) $(TEST_OBJ) 

$(objects): %.o: %.c $(HEADERS)
	$(CROSS_COMPILE)gcc -c $(CFLAGS) $(LDFLAGS) $< -o $@

install:
	cp *.h  $(HEADER_DIR)
	cp $(LIB_NAME) $(RELEASE_DIR)
#	install -d $(EXEC_DIR)
#	install $(executables) $(EXEC_DIR)

clean:
	rm -f *.o *.a
	@for DIR in $(executables); do \
		rm -f $(EXE_DIR)/$$DIR; \
	done

distclean: clean
	rm -f *.o

lint:
	@echo -----------------------------------------------------------
	splint  $(LINTFLAGS) $(INCDIRS) *.c
	
lintw: 
	@echo -----------------------------------------------------------
	-splint -weak $(LINTFLAGS) $(INCDIRS) *.c
 
lintc: 
	@echo -----------------------------------------------------------
	-splint -checks $(LINTFLAGS) $(INCDIRS) *.c
 
lints: 
	@echo -----------------------------------------------------------
	-splint -strict $(LINTFLAGS) $(INCDIRS) *.c
