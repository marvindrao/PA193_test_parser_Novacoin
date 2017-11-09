

make all || exit 1
make -C ../Novacoin_block_parser || exit 1
make -C ../Novacoin_block_parser test || exit 1
make test || exit 1
