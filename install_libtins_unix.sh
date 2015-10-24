#!/bin/bash
cd /tmp/
wget https://github.com/mfontanini/libtins/archive/master.zip
unzip master.zip
rm -f master.zip
cd libtins-master
mkdir build
cd build
cmake ../ -DLIBTINS_ENABLE_CXX11=1
make
sudo make install
sudo ldconfig
rm -rf libtins-master
