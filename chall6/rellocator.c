// gcc tcache.c -o data_bank
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include <malloc.h>

void * table[0x30];
int size[0x30];

int get_inp(char *buffer, int size) {
	int retval = read(0, buffer, size);
	if (retval == -1)
		exit(0);
	if ( buffer[retval-1] == '\n')
		buffer[retval-1] = '\0';
	return retval-1;
}

int get_inp_str(char *buffer, int size) {
	int retval = read(0, buffer, size);
	if (retval == -1)
		exit(0);
	buffer[retval] = '\0';
	return retval-1;
}

int get_int() {
	char buffer[32];
	get_inp(buffer, 32);
	return atoi(buffer);
}

int init(){
	alarm(180);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	puts("Magic Size:");
	int a = 0;
	a = get_int();
	malloc(a);
}



int  printmenu(){
	puts("1) Malloc\n2) Relloc\n3) View\n4) Exit");
	printf(">> ");
	unsigned int idx = 0;
	scanf("%d" , &idx);
	return idx;
}

void add(){
	int idx;
	puts("Index:");
	idx=get_int();
	while(idx >= 0 && idx < 0x30){
		if(table[idx] != NULL){
			puts("The idx is occupied\n");
			return;
		}
		puts("Size:");
		size[idx]=get_int();
		if(size[idx] < 0x00 || size[idx] > 0x58)
			{
				puts("Invalid size");
				exit(0);
			}
		table[idx]=malloc(size[idx]);
		if(!table[idx]){
			puts("Noi Noi");
			return;	
		}
		puts("Data:");
		get_inp(table[idx],size[idx]);
		return;
	}
}


void edit(){
	int idx;
	puts("Index:");
	idx=get_int();
	while(idx >= 0 && idx < 0x30){
		if(table[idx] == NULL){
			puts("The index is occupied\n");
			return;
		}
		puts("Size:");
		size[idx]=get_int();
		if(size[idx] < 0x00 || size[idx] > 0x58)
			{
				puts("Noi Noi");
				exit(0);
			}

		else{	
			table[idx]=realloc(table[idx],size[idx]);
			if(!table[idx]){
				puts("Error...");
				return;	
			}
			puts("Data:");
			get_inp_str(table[idx],size[idx]);
			return;
		}
	}

}

void view(){
	int idx;
	puts("Index:");
	idx=get_int();
	while(idx >= 0 && idx < 0x30){
		if(table[idx] == NULL){
			puts("Noi Noi");
			return;
		}
		printf("Data :");
		write(1,table[idx],size[idx]);
		return;
	}
}


int main(){
	init();

	puts("----------RELLOCATOR----------");
	puts("----------RELLOCATOR----------");
	puts("----------RELLOCATOR----------");
	puts("----------RELLOCATOR----------");
	puts("----------RELLOCATOR----------");
	puts("----------RELLOCATOR----------");
	do {
		switch(printmenu()) {
			case 1: add(); break;
			case 2: edit(); break;
			case 3: view(); break;
			case 4: exit(0);
			default: puts("Nope nope"); break;
		}
	} while(1);
	return 0;
}