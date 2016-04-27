#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1

#include "aes.h"

static void phex(uint8_t* str);
static void test_encrypt_ecb(void);
static void test_decrypt_ecb(void);
static void test_encrypt_ecb_verbose(void);
static void test_encrypt_cbc(void);
static void test_decrypt_cbc(void);



int main(void)
{/*
 test_encrypt_cbc();
 test_decrypt_cbc();
 test_decrypt_ecb();
 test_encrypt_ecb();*/
	test_encrypt_ecb_verbose();

	return 0;
}



// prints string as hex
static void phex(uint8_t* str)
{
	unsigned char i;
	for (i = 0; i < 16; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}

static void test_encrypt_ecb_verbose(void)
{
	// Example of more verbose verification

	uint8_t buf[16], buf2[16];

	// Key and plain text for all zeros
	uint8_t key_allzero[16] = { (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00 };
	uint8_t plain_text_allzero[16] = { (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00, (uint8_t)0x00 };

	// Random key and plain text
	uint8_t key[16] = { (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16, (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6, (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88, (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c };
	uint8_t plain_text[16] = { (uint8_t)0x6b, (uint8_t)0xc1, (uint8_t)0xbe, (uint8_t)0xe2, (uint8_t)0x2e, (uint8_t)0x40, (uint8_t)0x9f, (uint8_t)0x96, (uint8_t)0xe9, (uint8_t)0x3d, (uint8_t)0x7e, (uint8_t)0x11, (uint8_t)0x73, (uint8_t)0x93, (uint8_t)0x17, (uint8_t)0x2a };
	// for checking Hamming distance
	uint8_t plain_text2[16] = { (uint8_t)0x6b, (uint8_t)0xc0, (uint8_t)0xbe, (uint8_t)0xe2, (uint8_t)0x2e, (uint8_t)0x40, (uint8_t)0x9f, (uint8_t)0x96, (uint8_t)0xe9, (uint8_t)0x3d, (uint8_t)0x7e, (uint8_t)0x11, (uint8_t)0x73, (uint8_t)0x93, (uint8_t)0x17, (uint8_t)0x2a };

	memset(buf, 0, 16);
	memset(buf2, 0, 16);

	printf("Test for all zeros \n");
	printf("---------------------------------------------------------------------\n");

	// print text to encrypt, key and IV
	printf("ECB encrypt verbose:\n\n");
	printf("plain text:\n");
	phex(plain_text_allzero);
	printf("\n");

	printf("key:\n");
	phex(key_allzero);
	printf("\n");

	// print the resulting cipher as 16 byte strings
	printf("ciphertext:\n");
	AES128_ECB_encrypt(plain_text_allzero, key_allzero, buf);
	phex(buf);
	printf("\n");

	// print the resulting plaintext after decryption
	printf("decrypted plaintext:\n");
	AES128_ECB_decrypt(buf, key_allzero, buf2);
	phex(buf2);
	printf("\n\n");

	memset(buf, 0, 16);
	memset(buf2, 0, 16);

	printf("Test for Random key and plain text \n");
	printf("---------------------------------------------------------------------\n");

	// print text to encrypt, key and IV
	printf("ECB encrypt verbose:\n\n");
	printf("plain text:\n");
	phex(plain_text);
	printf("\n");

	printf("key:\n");
	phex(key);
	printf("\n");

	// print the resulting cipher as 16 byte strings
	printf("ciphertext:\n");
	AES128_ECB_encrypt(plain_text, key, buf);
	phex(buf);
	printf("\n");

	// print the resulting plaintext after decryption
	printf("decrypted plaintext:\n");
	AES128_ECB_decrypt(buf, key, buf2);
	phex(buf2);
	printf("\n\n");

	memset(buf, 0, 16);
	memset(buf2, 0, 16);

	printf("Test for Hamming distance of each round \n");
	printf("---------------------------------------------------------------------\n");

	printf("ECB encrypt verbose:\n\n");
	printf("plain text1 :\n");
	phex(plain_text);
	printf("\n");

	printf("plain text2 :\n");
	phex(plain_text2);
	printf("\n");

	printf("key:\n");
	phex(key);
	printf("\n");

	printf("ciphertext:\n");
	AES128_ECB_encrypt_Two(plain_text, plain_text2, key, buf, buf2);
	printf("\n");
}


static void test_encrypt_ecb(void)
{
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t in[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	uint8_t out[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
	uint8_t buffer[16];

	AES128_ECB_encrypt(in, key, buffer);

	printf("ECB decrypt: ");

	if (0 == strncmp((char*)out, (char*)buffer, 16))
	{
		printf("SUCCESS!\n");
	}
	else
	{
		printf("FAILURE!\n");
	}
}

static void test_decrypt_cbc(void)
{
	// Example "simulating" a smaller buffer...

	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t in[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };
	uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	uint8_t buffer[16];

	AES128_CBC_decrypt_buffer(buffer + 0, in + 0, 16, key, iv);

	printf("CBC decrypt: ");

	if (0 == strncmp((char*)out, (char*)buffer, 16))
	{
		printf("SUCCESS!\n");
	}
	else
	{
		printf("FAILURE!\n");
	}
}

static void test_encrypt_cbc(void)
{
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t in[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	uint8_t out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };
	uint8_t buffer[16];

	AES128_CBC_encrypt_buffer(buffer, in, 16, key, iv);

	printf("CBC encrypt: ");

	if (0 == strncmp((char*)out, (char*)buffer, 16))
	{
		printf("SUCCESS!\n");
	}
	else
	{
		printf("FAILURE!\n");
	}
}


static void test_decrypt_ecb(void)
{
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t in[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
	uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	uint8_t buffer[16];

	AES128_ECB_decrypt(in, key, buffer);

	printf("ECB decrypt: ");

	if (0 == strncmp((char*)out, (char*)buffer, 16))
	{
		printf("SUCCESS!\n");
	}
	else
	{
		printf("FAILURE!\n");
	}
}
