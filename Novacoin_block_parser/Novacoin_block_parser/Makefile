all:
	g++ -g -Wall -Wextra -D _DEBUG Novacoin_block_parser.cpp functions.cpp -o parser -lssl -lcrypto

test:
	./parser b101 b100
