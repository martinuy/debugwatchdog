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

CFLAGS=""
CXXFLAGS=""

if ! [[ -z "${COMPILE_MODE}" ]]; then
if [[ $COMPILE_MODE == "debug" ]]; then
    CFLAGS+="-g -DDEBUG -O3"
    CXXFLAGS+="-g"
    echo "Compiling in debug mode"
else
    echo "Compiling in release mode"
fi
fi

export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"

echo "Compiling lib..."
LIB_COMPILE_COMMAND="gcc ${CFLAGS} -o lib/libdebugwatchdog.so -Idriver -fPIC -shared lib/libdebugwatchdog.c -pthread"
echo "$LIB_COMPILE_COMMAND"
$LIB_COMPILE_COMMAND && chmod +x lib/libdebugwatchdog.so

echo "Compiling test..."
TEST_COMPILE_COMMAND="gcc ${CFLAGS} -o test/debugwatchdogtest -Wl,-rpath,\$ORIGIN -Ilib -Llib test/debugwatchdogtest.c -ldebugwatchdog -pthread"
echo "$TEST_COMPILE_COMMAND"
$TEST_COMPILE_COMMAND

echo "Compiling driver..."
cd driver && make all && $(xz --compress --stdout debugwatchdogdriver.ko > debugwatchdogdriver.ko.xz) && chmod +x debugwatchdogdriver.ko.xz && chmod +x debugwatchdogdriver.ko && cd ..

echo "Compiling UI..."
cd ui/debugwatchdogui && make && chmod +x debugwatchdogui && cd ../..
