#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>

int get_inp(char *buffer, int size) {
	int retval = read(0, buffer, size);
	if (retval == -1)
		exit(0);
	if ( buffer[retval-1] == '\n')
		buffer[retval-1] = '\0';
	return retval-1;
}

int get_int() {
	char buffer[32];
	get_inp(buffer, 32);
	return atoi(buffer);
}


int main(int argc, char const *argv[])
{
	printf("Enter the size to malloc:\n");
	long long int size = get_int();
	char *ptr = malloc(size);
	printf("%p\n", ptr);
	printf("Offset:\n");
	long long int offset = 0;
	scanf("%llx",&offset);
	printf("Data:\n");
	char data[16];
	get_inp(&ptr[offset],16);
	malloc(10);
	_exit(0);
}