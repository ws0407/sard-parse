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
static void good1()
{
    goto sink;
sink:
    {
        charVoid * structCharVoid = (charVoid *)malloc(sizeof(charVoid));
        if (structCharVoid == NULL) {exit(-1);}
        structCharVoid->voidSecond = (void *)SRC_STR;
        printLine((char *)structCharVoid->voidSecond);
        memcpy(structCharVoid->charFirst, SRC_STR, sizeof(structCharVoid->charFirst));
        structCharVoid->charFirst[(sizeof(structCharVoid->charFirst)/sizeof(char))-1] = '\0'; 
        printLine((char *)structCharVoid->charFirst);
        printLine((char *)structCharVoid->voidSecond);
        free(structCharVoid);
    }
}
int main(int argc, char * argv[])
{
    srand( (unsigned)time(NULL) );
    good1();
    return 0;
}
