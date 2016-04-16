GCC_FLAGS=-fPIC -fno-stack-protector -c
LD_FLAGS=-x --shared
GCC=gcc
LD=ld

all: pam_konami

pam_konami:
	$(GCC) $(GCC_FLAGS) -c $@.c
	$(LD) $(LD_FLAGS) -o $@.so $@.o
