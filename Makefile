BUILD = build
KOBJ = $(BUILD)/obj/kernel
COBJ = $(BUILD)/obj/client

SDK = macosx
KERNEL_ARCH = arm64e
CLIENT_ARCH = arm64

SYSROOT := $(shell xcrun --sdk $(SDK) --show-sdk-path)

CLANG := $(shell xcrun --sdk $(SDK) --find clang)
CLANGPP := $(shell xcrun --sdk $(SDK) --find clang++)

DSYMUTIL := $(shell xcrun --sdk $(SDK) --find dsymutil)

CC := $(CLANG)
CXX := $(CLANGPP)

NASM := nasm

PKG = com.home.inspector
TARGET = inspector

KFWK = $(SYSROOT)/System/Library/Frameworks/Kernel.framework
IOKIT_FWK = $(SYSROOT)/System/Library/Frameworks/IOKit.framework
DRIVERKIT_FWK = $(SYSROOT)/System/Library/Frameworks/DriverKit.framework
IOSURFACE_FWK = $(SYSROOT)/System/Library/Frameworks/IOSurface.framework

KERNEL_HEADERS = -I$(KFWK)/Headers -I$(IOKIT_FWK)/Headers -I$(DRIVERKIT_FWK)/Headers -I$(IOSURFACE_FWK)/Headers

KERNEL_CSOURCES := $(wildcard kernel/*.c)
KERNEL_COBJECTS := $(patsubst kernel/%.c, $(KOBJ)/%.o, $(KERNEL_CSOURCES))

KERNEL_CPPSOURCES := $(wildcard kernel/*.cpp)
KERNEL_CPPOBJECTS := $(patsubst kernel/%.cpp, $(KOBJ)/%.o, $(KERNEL_CPPSOURCES))

CLIENT_CSOURCES := $(wildcard client/*.c)
CLIENT_COBJECTS := $(patsubst client/%.c, $(COBJ)/%.o, $(CLIENT_CSOURCES))

CLIENT_CPPSOURCES := $(wildcard client/*.cpp)
CLIENT_CPPOBJECTS := $(patsubst client/%.cpp, $(COBJ)/%.o, $(CLIENT_CPPSOURCES))


CPATH := $(SYSROOT)/usr/include

CFLAGS += -g -I/usr/include -I/usr/local/include -isysroot $(SYSROOT) -arch $(KERNEL_ARCH) $(KERNEL_HEADERS) -O2 -fmodules -mkernel -I./kernel -nostdlib -DMACH_KERNEL_PRIVATE -O2 -D__KERNEL__ -DAPPLE -DNeXT $(KERNEL_)
CXXFLAGS += -g -std=c++20 $(KERNEL_HEADERS) -isysroot $(SYSROOT) -arch $(KERNEL_ARCH) -fno-builtin -fno-common -nostdlib -DAPPLE -DNeXT
LDFLAGS += -g -std=c++20 -isysroot $(SYSROOT) -arch $(KERNEL_ARCH) -fno-builtin -fno-common -L/usr/lib -L/usr/local/lib -D__KERNEL__ -DMACH_KERNEL_PRIVATE -Wl,-kext -DAPPLE -DNeXT  -target arm64e-apple-macos15.2 -Xlinker -reproducible -Xlinker -kext -nostdlib -lkmodc++ -lkmod -lcc_kext


.PHONY: all clean

all: clean $(KOBJ) $(BUILD)/$(TARGET).kext/Contents/MacOS $(BUILD)/$(TARGET).kext/Contents/MacOS/$(TARGET) $(BUILD)/$(TARGET).kext/Contents/Info.plist codesign set_owner

$(KERNEL_COBJECTS): $(KOBJ)/%.o: kernel/%.c
	mkdir -p $(KOBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_CPPOBJECTS): $(KOBJ)/%.o: kernel/%.cpp
	mkdir -p $(KOBJ)
	$(CXX) $(CFLAGS) $(CXXFLAGS) -g -c $< -o $@

$(CLIENT_COBJECTS): $(COBJ)/%.o: client/%.c
	mkdir -p $(COBJ)
	$(CC)  -isysroot $(SYSROOT) -c $< -o $@

$(CLIENT_CPPOBJECTS): $(KOBJ)/%.o: client/%.cpp
	mkdir -p $(COBJ)
	$(CXX) -isysroot $(SYSROOT) -g -c $< -o $@

$(KOBJ):
	rm -rf $(KOBJ)/*.o

$(COBJ):
	rm -rf $(COBJ)/*.o

$(BUILD)/$(TARGET).kext/Contents/MacOS:
	mkdir -p $@

$(BUILD)/$(TARGET).kext/Contents/MacOS/$(TARGET): $(KERNEL_COBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(KERNEL_COBJECTS)

$(BUILD)/$(TARGET).kext/Contents/Info.plist: Info.plist | $(BUILD)/$(TARGET).kext/Contents/MacOS
	cp -f $< $@

codesign: $(BUILD)/$(TARGET).kext/Contents/MacOS/$(TARGET)
	codesign --remove-signature $(BUILD)/$(TARGET).kext
	codesign --sign - --force --entitlements Info.plist $(BUILD)/$(TARGET).kext

set_owner: codesign
	sudo chown -R root:wheel $(BUILD)/$(TARGET).kext

$(BUILD)/$(TARGET): $(CLIENT_COBJECTS)
	$(CC) -isysroot $(SYSROOT) -o $@ $(CLIENT_COBJECTS)

client: $(BUILD)/$(TARGET)

clean_client:
	rm -rf $(COBJ)/*
	rm -rf $(BUILD)/$(TARGET)

clean_kernel:
	rm -rf $(KOBJ)/*
	sudo rm -rf $(BUILD)/$(TARGET).kext

clean: clean_client  clean_kernel

includes:
	for l in $(KERNEL_HEADERS); do echo $${l} | awk -F'-I' '{print $$2}';done
