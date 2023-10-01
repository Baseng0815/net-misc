obj-m += nsufw.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

remove:
	- rmmod ./nsufw.ko

insert: remove
	insmod ./nsufw.ko
