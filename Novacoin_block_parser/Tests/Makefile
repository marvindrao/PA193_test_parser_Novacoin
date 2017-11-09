all:
	g++ -g -Wall -Wextra -D _DEBUG Test_Novacoin_block_parser.cpp ../Novacoin_block_parser/functions.cpp -o testParser -lssl -lcrypto

test:
	./testParser b2
