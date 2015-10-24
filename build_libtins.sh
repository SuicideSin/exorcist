#!/bin/bash
cd libtins-master
mkdir build
cd build
cmake ../ -DLIBTINS_ENABLE_CXX11=1
make
