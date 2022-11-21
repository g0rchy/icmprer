#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>

#define KEY "abc"

int main(void) {
    char key[16];
    char *encrypted;
    char salt[] = "$1$........";

    printf("enter something: ");
    scanf("%s", key);
    encrypted = crypt(key, salt);
    printf("%s", encrypted);
}