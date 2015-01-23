git clone --depth=1 --branch=master git@github.com:apache/thrift tmp
cp -R tmp/lib/php/lib/* src/
rm -Rf tmp
