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

NM := $(shell xcrun --sdk $(SDK) --find nm)

# Exported KPI / kernel symbols collection
KERNEL_IMAGE ?= /System/Library/Kernels/kernel
KPI_OUT = $(BUILD)/kpi.txt

# OSBundleLibraries is generated from every com.apple.kpi.* symbol set available
# on the running system, so the kext binds to this host's exact KPI versions.
KPI_PLUGINS = /System/Library/Extensions/System.kext/PlugIns
KPI_WATERMARK = __KPI_LIBRARIES__

# PKG = com.apple.security.inspector
TARGET = inspector
TARGET_LIB = libinspector.dylib

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
CXXFLAGS += -g -std=c++20 $(KERNEL_HEADERS) -isysroot $(SYSROOT) -arch $(KERNEL_ARCH) -fno-builtin -mkernel -I./kernel -fno-common -nostdlib -DAPPLE -DNeXT
LDFLAGS += -g -std=c++20 -isysroot $(SYSROOT) -arch $(KERNEL_ARCH) -fno-builtin -fno-common -L/usr/lib -L/usr/local/lib -D__KERNEL__ -DMACH_KERNEL_PRIVATE -Wl,-kext -DAPPLE -DNeXT  -target arm64e-apple-macos15.2 -Xlinker -reproducible -Xlinker -kext -nostdlib -lkmodc++ -lkmod -lcc_kext


.PHONY: all clean

all: clean $(KOBJ) $(BUILD)/$(TARGET).kext/Contents/MacOS $(BUILD)/$(TARGET).kext/Contents/MacOS/$(TARGET) $(BUILD)/$(TARGET).kext/Contents/Info.plist codesign set_owner

$(KERNEL_COBJECTS): $(KOBJ)/%.o: kernel/%.c
	mkdir -p $(KOBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_CPPOBJECTS): $(KOBJ)/%.o: kernel/%.cpp
	mkdir -p $(KOBJ)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(CLIENT_COBJECTS): $(COBJ)/%.o: client/%.c
	mkdir -p $(COBJ)
	$(CC)  -isysroot $(SYSROOT) -c $< -o $@

$(CLIENT_CPPOBJECTS): $(KOBJ)/%.o: client/%.cpp
	mkdir -p $(COBJ)
	$(CXX) -isysroot $(SYSROOT) -c $< -o $@

$(KOBJ):
	rm -rf $(KOBJ)/*.o

$(COBJ):
	rm -rf $(COBJ)/*.o

$(BUILD)/$(TARGET).kext/Contents/MacOS:
	mkdir -p $@

$(BUILD)/$(TARGET).kext/Contents/MacOS/$(TARGET): $(KERNEL_COBJECTS) $(KERNEL_CPPOBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $(KERNEL_COBJECTS) $(KERNEL_CPPOBJECTS)

$(BUILD)/$(TARGET).kext/Contents/Info.plist: Info.plist | $(BUILD)/$(TARGET).kext/Contents/MacOS
	@libs=""; \
	for p in $(KPI_PLUGINS)/*.kext/Info.plist; do \
		id=$$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$$p" 2>/dev/null); \
		case "$$id" in \
			com.apple.kpi.private|com.apple.kpi.kasan|com.apple.kpi.kcov) continue;; \
			com.apple.kpi.*) ;; \
			*) continue;; \
		esac; \
		ver=$$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$$p" 2>/dev/null); \
		libs="$$libs\t\t<key>$$id</key>\n\t\t<string>$$ver</string>\n"; \
	done; \
	[ -n "$$libs" ] || { echo "ERROR: no com.apple.kpi.* libraries found under $(KPI_PLUGINS)"; exit 1; }; \
	awk -v repl="$$libs" '{ if ($$0 ~ /$(KPI_WATERMARK)/) printf "%s", repl; else print }' $< > $@; \
	echo "Info.plist: injected $$(printf "%b" "$$libs" | grep -c '<key>') available KPI libraries"

codesign: $(BUILD)/$(TARGET).kext/Contents/MacOS/$(TARGET) $(BUILD)/$(TARGET).kext/Contents/Info.plist
	codesign --remove-signature $(BUILD)/$(TARGET).kext
	codesign --sign - --force --entitlements $(BUILD)/$(TARGET).kext/Contents/Info.plist $(BUILD)/$(TARGET).kext

set_owner: codesign
	sudo chown -R root:wheel $(BUILD)/$(TARGET).kext

$(BUILD)/$(TARGET): $(CLIENT_COBJECTS)
	$(CC) -isysroot $(SYSROOT) -o $@ $(CLIENT_COBJECTS)

$(BUILD)/$(TARGET_LIB): $(CLIENT_COBJECTS)
	$(CC) -isysroot $(SYSROOT) -shared -undefined dynamic_lookup -o $@ $(CLIENT_COBJECTS)

client: $(BUILD)/$(TARGET)

client_lib: $(BUILD)/$(TARGET_LIB)

clean_client:
	rm -rf $(COBJ)/*
	rm -rf $(BUILD)/$(TARGET)

clean_kernel:
	rm -rf $(KOBJ)/*
	sudo rm -rf $(BUILD)/$(TARGET).kext

clean: clean_client  clean_kernel

includes:
	for l in $(KERNEL_HEADERS); do echo $${l} | awk -F'-I' '{print $$2}';done
