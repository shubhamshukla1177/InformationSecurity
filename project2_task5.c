//Task5

#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 512

void printBN(char *msg, BIGNUM *a)
{
	char * num_str = BN_bn2hex(a);
	printf("%s %s\n", msg, num_str);
	OPENSSL_free(num_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *C = BN_new();
   
    BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_dec2bn(&e,"65537");
    BN_hex2bn(&M,"4c61756e63682061206d697373696c652e");
    //BN_hex2bn(&S,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    //Corrupting the Signature by Changing 2F to 3F
    BN_hex2bn(&S,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

 
    BN_mod_exp(C,S,e,n,ctx);
    printBN("Message: ", M);
    printBN("Derived Message: ", C);

    if(BN_cmp(C,M)==0)
    {
	    printf("Congrats! Signature is valid. \n");
    }
    else
    {
	    printf("Alert! Signature is not valid. \n");
    }

    return 0;
}