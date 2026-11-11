# Hardened defaults for a plain `make`; dpkg-buildflags replaces them in the
# package build with its own (hardening=+all).
CPPFLAGS ?= -D_FORTIFY_SOURCE=2
CXXFLAGS ?= -O2 -g -fstack-protector-strong -fstack-clash-protection
LDFLAGS ?= -Wl,-z,relro,-z,now
# Only pam_sm_authenticate and pam_sm_setcred are exported.
CXXFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -std=c++17 \
            -fvisibility=hidden -fvisibility-inlines-hidden

PAMDIR ?= /usr/lib/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)/security
LIBEXECDIR ?= /usr/libexec/pam-entra-sudo

all: pam_entra_sudo.so pam-entra-sudo-fetch

src/%.o: src/%.cpp src/*.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

pam_entra_sudo.so: src/pam_entra_sudo.o src/config.o src/pam_entra_sudo.map
	$(CXX) -shared $(LDFLAGS) -Wl,--version-script=src/pam_entra_sudo.map \
		src/pam_entra_sudo.o src/config.o -lpam -o $@

pam-entra-sudo-fetch: src/fetch.o
	$(CXX) -pie $(LDFLAGS) $^ -lcurl -o $@

install: all
	install -D -m 0644 -t $(DESTDIR)$(PAMDIR) pam_entra_sudo.so
	install -D -m 0755 pam-entra-sudo-fetch $(DESTDIR)$(LIBEXECDIR)/fetch

clean:
	rm -f src/*.o pam_entra_sudo.so pam-entra-sudo-fetch

.PHONY: all install clean
