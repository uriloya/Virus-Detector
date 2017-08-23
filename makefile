# All Targets
all: virusDetector

# Tool invocations
# Executable "virusDetector" depends on the files task1c.o
virusDetector: task1c.o
	gcc -g -m32 -Wall -o virusDetector task1c.o

# Depends on the source and header files
task1c.o: task1c.c
	gcc -m32 -g -Wall -ansi -c -o task1c.o task1c.c 

#tell make that "clean" is not a file name!
.PHONY: clean

#Clean the build directory
clean: 
	rm -f *.o virusDetector