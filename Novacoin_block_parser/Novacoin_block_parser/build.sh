echo "Environment: `uname -a`"
echo "Compiler: `$CXX --version`"

make all|| exit 1
make -C ../Tests/
make test || exit 1
