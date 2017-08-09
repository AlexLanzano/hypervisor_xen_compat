obj-m += pvclock.o

EXTRA_CFLAGS= -Wall -Werror

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
