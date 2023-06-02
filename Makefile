# obj-m += netfilterKmod.o
# obj-m += netfilterKmod2.o
# obj-m += netfilterKmod3.o
# obj-m += netfilterKmod4.o
obj-m += myNetfilterKmod.o
KDIR = /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(shell pwd)	clean
	make -C $(KDIR)	M=$(shell pwd)	modules

clean:
	make -C $(KDIR) M=$(shell pwd)	clean
