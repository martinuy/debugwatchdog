#!/bin/bash

#
#   Martin Balao (martin.uy) - © Copyright 2017
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

########################
##       Configs      ##
########################

#export KERNEL_HEADERS_PATH=/path/to/kernel/headers

export COMPILE_MODE="debug" # (debug / release)

######################
##      Script      ##
######################

if [[ -z "${KERNEL_HEADERS_PATH}" ]]; then
    echo "Must define KERNEL_HEADERS_PATH environmental variable to compile."
exit
fi

cd src

./clean.sh
./compile.sh

cd ..

rm -rf bin/debugwatchdoglib.h
rm -rf bin/libdebugwatchdog.so
rm -rf bin/debugwatchdogtest
rm -rf bin/debugwatchdogdriver.ko
rm -rf bin/debugwatchdogui

cp src/lib/debugwatchdoglib.h bin/
cp src/lib/libdebugwatchdog.so bin/
cp src/test/debugwatchdogtest bin/
cp src/driver/debugwatchdogdriver.ko bin/
cp src/ui/debugwatchdogui/debugwatchdogui bin/
