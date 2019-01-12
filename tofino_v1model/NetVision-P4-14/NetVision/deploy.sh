cp netvision.conf $SDE_INSTALL/share/p4/targets/tofino/
cd $SDE/pkgsrc/p4-build
./configure --prefix=$SDE_INSTALL --with-tofino P4_NAME=netvision P4_PATH=~/netvision-rtt/netvision.p4 --enable-thrift
make -j8
make install