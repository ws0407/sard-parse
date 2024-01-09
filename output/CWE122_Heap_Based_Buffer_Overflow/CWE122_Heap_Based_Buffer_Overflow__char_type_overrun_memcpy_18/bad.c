#include "std_testcase.h"
#ifndef _WIN32
#include <wchar.h>
#endif
#define SRC_STR "0123456789abcdef0123456789abcde"
typedef struct _charVoid
{
    char charFirst[16];
    void * voidSecond;
    void * voidThird;
} charVoid;
void CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_18_bad()
{
    goto sink;
sink:
    {
        charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
        if (structCharVoid == NULL) {exit(-1);}
        structCharVoid->voidSecond = (void *)SRC_STR;
        printLine((char *)structCharVoid->voidSecond);
        memcpy(structCharVoid->charFirst, SRC_STR, sizeof(*structCharVoid));
        structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(char))-1] = '\0'; 
        printLine((char *)structCharVoid->charFirst);
        printLine((char *)structCharVoid->voidSecond);
        free(structCharVoid);
    }
}
int main(int argc, char * argv[])
{
    srand( (unsigned)time(NULL) );
    CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_18_bad();
    return 0;
}
