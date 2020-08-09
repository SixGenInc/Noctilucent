# Constants
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
TLS_DIR      = $(abspath $(dir $(MK_FILE_PATH))/tls)
WEBSOCKET_DIR      = $(abspath $(dir $(MK_FILE_PATH))/websocket)
TOP_DIR      = $(abspath $(dir $(MK_FILE_PATH)))
DEV_DIR      = $(abspath $(dir $(MK_FILE_PATH))/_dev)
# Results will be produced in this directory (can be provided by a caller)
BUILD_DIR   ?= $(abspath $(dir $(MK_FILE_PATH))/_dev/GOROOT)

# Compiler
GO ?= go
DOCKER ?= docker
GIT ?= git

# Build environment
OS          ?= $(shell $(GO) env GOHOSTOS)
ARCH        ?= $(shell $(GO) env GOHOSTARCH)
OS_ARCH     := $(OS)_$(ARCH)
VER_OS_ARCH := $(shell $(GO) version | cut -d' ' -f 3)_$(OS)_$(ARCH)
VER_MAJOR   := $(shell $(GO) version | cut -d' ' -f 3 | cut -d. -f1-2)
GOROOT_ENV  ?= $(shell $(GO) env GOROOT)
GOROOT_LOCAL = $(BUILD_DIR)/$(OS_ARCH)
# Flag indicates wheter invoke "go install -race std". Supported only on amd64 with CGO enabled
INSTALL_RACE:= $(words $(filter $(ARCH)_$(shell go env CGO_ENABLED), amd64_1))
TMP_DIR		:= $(shell mktemp -d)

# SIDH repository
SIDH_REPO  ?= https://github.com/cloudflare/sidh.git
SIDH_REPO_TAG ?= Release_1.0
# NOBS repo (SIKE depends on SHA3)
NOBS_REPO  ?= https://github.com/henrydcase/nobscrypto.git
NOBS_REPO_TAG ?= Release_0.1

##############################
#
# Build targets
#
##############################
$(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH): clean

# Create clean directory structure
	mkdir -p "$(GOROOT_LOCAL)/pkg"

# Copy src/tools from system GOROOT
	# macOS cp requires -R instead of -r. It makes no difference for GNU cp.
	cp -HR $(GOROOT_ENV)/src $(GOROOT_LOCAL)/src
	cp -HR $(GOROOT_ENV)/pkg/include $(GOROOT_LOCAL)/pkg/include
	cp -HR $(GOROOT_ENV)/pkg/tool $(GOROOT_LOCAL)/pkg/tool

# Swap TLS implementation
	rm -r $(GOROOT_LOCAL)/src/crypto/tls/*
	rsync -rltgoD $(TLS_DIR)/ $(GOROOT_LOCAL)/src/crypto/tls/ --exclude=$(lastword $(subst /, ,$(DEV_DIR)))

# Swap Websocket implementation
	# rm -r $(GOROOT_LOCAL)/src/golang.org/x/net/websocket/*
	# rsync -rltgoD $(WEBSOCKET_DIR)/ $(GOROOT_LOCAL)/golang.org/x/net/websocket/ --exclude=$(lastword $(subst /, ,$(DEV_DIR)))

# Apply additional patches
	for p in $(wildcard $(DEV_DIR)/patches/*); do patch -d "$(GOROOT_LOCAL)" -p1 < "$$p"; done

# Adjust internal paths https://github.com/cloudflare/tls-tris/issues/166
ifeq ($(VER_MAJOR), go1.12)
	perl -pi -e 's,"golang\.org/x/crypto/,"internal/x/crypto/,' $(GOROOT_LOCAL)/src/crypto/tls/*.go
else ifeq ($(VER_MAJOR), go1.11)
	perl -pi -e 's,"golang\.org/x/crypto/,"golang_org/x/crypto/,' $(GOROOT_LOCAL)/src/crypto/tls/*.go
endif
	perl -pi -e 's,"golang\.org/x/sys/cpu","internal/cpu",' $(GOROOT_LOCAL)/src/crypto/tls/*.go
# Use vendored copy of SIDH and SIKE.
	perl -pi -e 's,"github\.com/,"github_com/,' $(GOROOT_LOCAL)/src/crypto/tls/*.go

# Vendor NOBS library
	$(GIT) clone $(NOBS_REPO) $(TMP_DIR)/nobs
	cd $(TMP_DIR)/nobs; $(GIT) checkout tags/$(NOBS_REPO_TAG)
	perl -pi -e 's/sed -i/perl -pi -e/' $(TMP_DIR)/nobs/Makefile
	cd $(TMP_DIR)/nobs; make vendor-sidh-for-tls
#	cp -rf $(TMP_DIR)/nobs/tls_vendor/. $(GOROOT_LOCAL)/src/vendor/
	cp -rf $(TMP_DIR)/nobs/tls_vendor/. $(GOROOT_LOCAL)/src/

# Vendor SIDH library
	$(GIT) clone $(SIDH_REPO) $(TMP_DIR)/sidh
	cd $(TMP_DIR)/sidh; $(GIT) checkout tags/$(SIDH_REPO_TAG)
	perl -pi -e 's/sed -i/perl -pi -e/' $(TMP_DIR)/sidh/Makefile
	cd $(TMP_DIR)/sidh; make vendor
#	cp -rf $(TMP_DIR)/sidh/build/vendor/. $(GOROOT_LOCAL)/src/vendor/
	cp -rf $(TMP_DIR)/sidh/build/vendor/. $(GOROOT_LOCAL)/src/

# Create go package
	GOARCH=$(ARCH) GOROOT="$(GOROOT_LOCAL)" $(GO) install -v std
ifeq ($(INSTALL_RACE),1)
	GOARCH=$(ARCH) GOROOT="$(GOROOT_LOCAL)" $(GO) install -race -v std
endif
	rm -rf $(TMP_DIR)
	@touch "$@"


build-all: \
	build-client \
	build-server 
	
# Builds client
client: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	cd $(TOP_DIR)/client && \
		mkdir -p build && \
		GOROOT="$(GOROOT_LOCAL)" $(GO) get -d -v && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=linux CGO_ENABLED=0 $(GO) build -trimpath -o noctilucent-client-linux -v -i . && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=darwin CGO_ENABLED=0 $(GO) build  -trimpath -o noctilucent-client-macOS -v -i . && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=windows CGO_ENABLED=0 $(GO) build  -trimpath -o noctilucent-client-windows.exe -v -i . && \
		mv noctilucent-client* ./build

# Builds server
server: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	cd $(TOP_DIR)/server && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=linux CGO_ENABLED=0 $(GO) build -trimpath -o noctilucent-test-server-linux -v -i .


# Cloak
cloak: $(BUILD_DIR)/$(OS_ARCH)/.ok_$(VER_OS_ARCH)
	cd $(TOP_DIR)/Cloak && \
		mkdir -p build && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=linux CGO_ENABLED=0 go build -trimpath -o noctilucent-cloak-client-linux -ldflags "-X main.version=${version}" ./cmd/ck-client && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=darwin CGO_ENABLED=0 go build -trimpath -o noctilucent-cloak-client-macOS -ldflags "-X main.version=${version}" ./cmd/ck-client && \
		GOROOT="$(GOROOT_LOCAL)" GOOS=windows CGO_ENABLED=0 go build -trimpath -o noctilucent-cloak-client-windows.exe -ldflags "-X main.version=${version}" ./cmd/ck-client && \
		mv noctilucent-cloak-client* ./build

##############################
#
# Utils
#
##############################
clean:
	rm -rf $(BUILD_DIR)/$(OS_ARCH)

clean-all: clean
	rm -rf $(BUILD_DIR)

fmtcheck:
	$(DEV_DIR)/utils/fmtcheck.sh

# .PHONY: $(BUILD_DIR) clean build build-test test test-unit test-bogo test-interop
