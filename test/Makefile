SRC_DIR = ../src

CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -pthread -std=c++17
# Point the module at mock_server.py instead of Entra.
CPPFLAGS += -I$(SRC_DIR) -DENTRA_AUTHORITY='"http://localhost:8042"' \
            -DENTRA_FETCH='"$(CURDIR)/pam-entra-sudo-fetch"'

LDLIBS = -lpam
GTEST_LIBS = -lgtest_main -lgtest -pthread

TESTS = test_config test_pam_entra_sudo

all: pam-entra-sudo-fetch $(TESTS)
	for test in $(TESTS); do ./$${test} || exit 1; done

%.o: $(SRC_DIR)/%.cpp $(SRC_DIR)/*.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

test_%.o: test_%.cpp $(SRC_DIR)/*.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

test_config: test_config.o config.o
	$(CXX) $(CXXFLAGS) $^ $(GTEST_LIBS) -o $@

test_pam_entra_sudo: test_pam_entra_sudo.o pam_entra_sudo.o config.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) $(GTEST_LIBS) -o $@

pam-entra-sudo-fetch: fetch.o
	$(CXX) $(CXXFLAGS) $^ -lcurl -o $@

clean:
	rm -f *.o $(TESTS) pam-entra-sudo-fetch

.PHONY: all clean
