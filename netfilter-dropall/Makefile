obj-m += netfilter-dropall.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

remove:
	- rmmod ./netfilter-dropall.ko

insert: remove
	insmod ./netfilter-dropall.ko
