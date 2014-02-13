git clone --depth=1 --branch=master git://git.apache.org/thrift.git tmp
cp -R tmp/lib/php/lib/* src/
rm -Rf tmp
