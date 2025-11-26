#!/bin/bash

cd pjproject

make distclean
./configure --enable-shared
make dep && make
make install

cd ..
