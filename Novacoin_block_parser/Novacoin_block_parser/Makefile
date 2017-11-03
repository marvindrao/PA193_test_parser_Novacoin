all:
	$(CXX) -g -Wall -Wextra -D _DEBUG Novacoin_block_parser.cpp -o parser -lssl -lcrypto

test:
	./parser b2
