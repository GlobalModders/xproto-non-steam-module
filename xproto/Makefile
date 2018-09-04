HLSDK=/usr/include/hlsdk/multiplayer
MM_ROOT=/usr/include/metamod/metamod
AMXX_DIR=/usr/include/amxmodx

### EDIT BELOW FOR OTHER PROJECTS ###

OPT_FLAGS = -O3 -funroll-loops -s -pipe -fomit-frame-pointer -fno-strict-aliasing 
DEBUG_FLAGS = -g -ggdb3 -DMODULE_DEBUG -Dlinux
CPP = g++
NAME = xproto

BIN_SUFFIX_32 = i386.so
BIN_SUFFIX_64 = amd64.so

OBJECTS = dllapi.cpp engine_api.cpp h_export.cpp meta_api.cpp xproto.cpp sdk_util.cpp

INCLUDE = -I. -I$(HLSDK) -I$(HLSDK)/dlls -I$(HLSDK)/engine -I$(HLSDK)/game_shared \
	-I$(MM_ROOT) -I$(HLSDK)/common -I$(HLSDK)/pm_shared -Iincludes 

GCC_VERSION_FULL := $(shell $(CPP) -dumpversion)
GCC_VERSION := $(shell $(CPP) -dumpversion >&1 | cut -b1)
SVNDEV := -D'SVN_REV="$(shell svnversion -n .) gcc-$(GCC_VERSION_FULL)"'

#ifeq "$(GCC_VERSION)" "4"
        OPT_FLAGS += -fvisibility=hidden -fvisibility-inlines-hidden
#endif

ifeq "$(DEBUG)" "true"
	BIN_DIR = Debug
	CFLAGS = $(DEBUG_FLAGS)
else
	BIN_DIR = Release
	CFLAGS = $(OPT_FLAGS)
#	CFLAGS = $(DEBUG_FLAGS)
endif

CFLAGS += -DNDEBUG -Wno-non-virtual-dtor -DHAVE_STDINT_H $(SVNDEV)

ifeq "$(AMD64)" "true"
	BINARY = $(NAME)_$(BIN_SUFFIX_64)
	CFLAGS += -DPAWN_CELL_SIZE=64 -DHAVE_I64 -m64
else
	BINARY = $(NAME)_$(BIN_SUFFIX_32)
	CFLAGS += -DPAWN_CELL_SIZE=32 -DJIT -DASM32
	OPT_FLAGS += -march=i586
endif

OBJ_LINUX := $(OBJECTS:%.cpp=$(BIN_DIR)/%.o)

$(BIN_DIR)/%.o: %.cpp
	$(CPP) $(INCLUDE) $(CFLAGS) -o $@ -c -fPIC  $<

all:
	mkdir -p $(BIN_DIR)
	mkdir -p Release
	mkdir -p Debug
	$(MAKE) debug

amd64:
	$(MAKE) all AMD64=true

xproto: $(OBJ_LINUX)
	$(CPP) $(INCLUDE) $(CFLAGS) $(OBJ_LINUX) $(LINK) -shared -lpthread -o$(BIN_DIR)/$(BINARY)

debug:	
	$(MAKE) xproto DEBUG=true

default: all

clean:
	rm -rf Release/*.o
	rm -rf Release/$(NAME)_$(BIN_SUFFIX_32)
	rm -rf Release/$(NAME)_$(BIN_SUFFIX_64)
	rm -rf Debug/*.o
	rm -rf Debug/$(NAME)_$(BIN_SUFFIX_32)
	rm -rf Debug/$(NAME)_$(BIN_SUFFIX_64)
