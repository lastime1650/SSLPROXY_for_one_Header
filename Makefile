# =============================================================================
# SSLPROXY C++ Wrapper Makefile
# =============================================================================

VCPKG_ROOT = /root/VATEX/vcpkg
VCPKG_TRIPLET = x64-linux
export PKG_CONFIG_PATH = $(VCPKG_ROOT)/installed/$(VCPKG_TRIPLET)/lib/pkgconfig



CXX      := g++
CLANG = clang
# -fpermissive: void* 자동 형변환 등 C 스타일 코드를 허용 (오류를 경고로 바꿈)
# -Wno-invalid-conversion: 존재하지 않는 플래그 제거함
CXXFLAGS := -std=gnu++20 -O0 -g -w -fpermissive \
            -D_GNU_SOURCE -DOPENSSL_THREADS

PACKAGES = PcapPlusPlus fmt rdkafka++ rdkafka liblz4 libzstd zlib openssl libbpf
CXXFLAGS += $(shell pkg-config --cflags $(PACKAGES))
LDFLAGS = -Wl,-rpath,$(VCPKG_ROOT)/installed/$(VCPKG_TRIPLET)/lib
LDLIBS = $(shell pkg-config --libs $(PACKAGES))

# OS Detection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    CXXFLAGS += -DHAVE_NETFILTER -DIP_TRANSPARENT
    LDFLAGS += -ldl
endif

ifeq ($(UNAME_S),Darwin)
    CXXFLAGS += -DHAVE_PF -DHAVE_DARWIN_LIBPROC
endif

ifeq ($(UNAME_S),FreeBSD)
    CXXFLAGS += -DHAVE_PF -DHAVE_LOCAL_PROCINFO
    INCLUDES += -I/usr/local/include
    LDFLAGS  += -L/usr/local/lib
endif

# Libraries
LIBS := -lssl -lcrypto -levent -levent_openssl -levent_pthreads -pthread -lnet -lpcap -lsqlite3

TARGET := sslproxy
SRC    := SSLPROXY_main.cpp
HDR    := SSLPROXY.hpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	@echo "Building $(TARGET)..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC) -o $(TARGET) $(LDFLAGS) $(LDLIBS) $(LIBS)

clean:
	rm -f $(TARGET) *.o