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

obj-m += debugwatchdogdriver.o
debugwatchdogdriver-objs := debugwatchdogdriver_main.o stub_ptregs_64_hooks.o

ccflags-y := ${CFLAGS}

all:
	make -C ${KERNEL_HEADERS_PATH} M=$(PWD) modules

clean:
	make -C ${KERNEL_HEADERS_PATH} M=$(PWD) clean
