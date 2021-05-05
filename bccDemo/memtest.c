#include <stdio.h>
#include <unistd.h>
#include <malloc.h>

int main(void){
    int i = 100;
    while (1){
        void *ptr = malloc(1000);
        //void *ptr2 = malloc(100);
        //void *ptr3 = malloc(10);
        //void *ptr4 = malloc(1);
        sleep(1);
        free(ptr);
    }
}