#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

int main(void){
    uint32_t  file_size = 6;
    void* x ;
    memcpy(x,&file_size,32);
}