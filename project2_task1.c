//TASK1

#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 512

BIGNUM* generate_private_key(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{
	//In this function, we are accepting two large prime numbers and computing a private key.	
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* sub_op1 = BN_new();
	BIGNUM* sub_op2 = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* mul_op = BN_new();
	BIGNUM* mod_inv_op = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(sub_op1, p, one);
	BN_sub(sub_op2, q, one);
	BN_mul(mul_op, sub_op1, sub_op2, ctx);

	BN_mod_inverse(mod_inv_op, e, mul_op, ctx);
	BN_CTX_free(ctx);
	return mod_inv_op;
}

void printBN(char *msg, BIGNUM *a)
{
	char * num_str = BN_bn2hex(a);
	printf("%s %s\n", msg, num_str);
	OPENSSL_free(num_str);
}

int main () 
{
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	
	//assigning p and q (prime numbers) here
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	
	//assigning e (modulus) here
	BN_hex2bn(&e, "0D88C3");

	BIGNUM* d = generate_private_key(p, q, e);
	printBN("Private Key (d):", d);

	return 0;
}