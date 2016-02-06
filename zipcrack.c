#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct key_state {
	uint32_t key0;
	uint32_t key1;
	uint32_t key2;
};

static uint32_t crctab[256];
static uint32_t crcinvtab[256];
static int have_table = 0;

static inline uint32_t crc32(uint32_t pval, uint8_t c)
{
	return (pval >> 8) ^ crctab[(pval & 0xff) ^ c];
}

static inline uint32_t crc32inv(uint32_t crc32, uint8_t c)
{
	return (crc32 << 8) ^ crcinvtab[crc32 >> 24] ^ c;
}

void init_crc()
{
	uint32_t rem;
	int i, j;

	/* Calculate CRC table. */
	for (i = 0; i < 256; i++) {
		rem = i;  /* remainder from polynomial division */

		for (j = 0; j < 8; j++) {
			if (rem & 1) {
				rem >>= 1;
				rem ^= 0xedb88320;
			} else {
				rem >>= 1;
			}
		}

		crctab[i] = rem;
		crcinvtab[rem >> 24] = (rem << 8) ^ i;
	}

	have_table = 1;
}

uint32_t crc_32(const uint8_t *data, size_t len)
{
	uint32_t crc = 0;
	size_t i;

	crc = ~crc;

	for (i = 0; i < len; i++)
		crc = (crc >> 8) ^ crctab[(crc & 0xff) ^ data[i]];

	return ~crc;
}

void update_keys(struct key_state *keys, uint8_t p)
{
	keys->key0 = crc32(keys->key0, p);
	keys->key1 = (keys->key1 + (keys->key0 & 0xff)) * 134775813 + 1;
	keys->key2 = crc32(keys->key2, (char)(keys->key1 >> 24));
}

void downdate_keys(struct key_state *keys, uint8_t p)
{
	keys->key2 = crc32inv(keys->key2, keys->key1 >> 24);
	keys->key1 = (keys->key1 - 1) * 3645876429 - (keys->key0 & 0xff);
	keys->key0 = crc32inv(keys->key0, p);
}

void initialize_keys(struct key_state *keys, const char *password, size_t len)
{
	size_t i;

	if (keys == NULL)
		return;

	keys->key0 = 0x12345678;
	keys->key1 = 0x23456789;
	keys->key2 = 0x34567890;

	if (password == NULL || len == 0)
		return;

	for (i = 0; i < len; i++)
		update_keys(keys, password[i]);
}

unsigned char decrypt_byte(struct key_state *keys)
{
	unsigned short temp;

	temp = keys->key2 | 2;
	return (temp * (temp ^ 1)) >> 8;
}

int test_password(const char *password, size_t plen, const uint8_t *encrypted_file, uint32_t flen, uint32_t crc32, uint8_t *decrypted_file)
{
	struct key_state keys;
	int i;

	initialize_keys(&keys, password, plen);

	for (i = 0; i < 12; i++)
		update_keys(&keys, encrypted_file[i] ^ decrypt_byte(&keys));

	for (; i < flen; i++) {
		decrypted_file[i - 12] = encrypted_file[i] ^ decrypt_byte(&keys);
		update_keys(&keys, decrypted_file[i - 12]);
	}

	if (crc_32(decrypted_file, flen - 12) == crc32)
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	FILE *cryptFile, *dictFile;
	uint16_t name_len, extra_len;
	uint32_t crc32, compressed_size;
	uint8_t *encrypted_file, *decrypted_file;
	char password[100];

	if (argc < 3) {
		printf("Usage: zipcrack <encrypted zip> <password list>\n");
		return 0;
	}

	cryptFile = fopen(argv[1], "r");

	if (!cryptFile) {
		perror("fopen");
		return -1;
	}

	fseek(cryptFile, 14, SEEK_SET);
	fread(&crc32, sizeof crc32, 1, cryptFile);
	fread(&compressed_size, sizeof compressed_size, 1, cryptFile);

	encrypted_file = malloc(compressed_size);

	if (!encrypted_file) {
		perror("malloc");
		fclose(cryptFile);
		return -1;
	}

	decrypted_file = malloc(compressed_size - 12);

	if (!decrypted_file) {
		perror("malloc");
		free(decrypted_file);
		fclose(cryptFile);
		return -1;
	}

	fseek(cryptFile, 26, SEEK_SET);
	fread(&name_len, sizeof name_len, 1, cryptFile);
	fread(&extra_len, sizeof extra_len, 1, cryptFile);
	fseek(cryptFile, name_len + extra_len, SEEK_CUR);
	fread(encrypted_file, compressed_size, 1, cryptFile);
	fclose(cryptFile);

	dictFile = fopen(argv[2], "r");

	if (!dictFile) {
		perror("fopen");
		free(encrypted_file);
		free(decrypted_file);
		return -1;
	}

	init_crc();

	while (fgets(password, sizeof password - 1, dictFile) != 0) {
		password[sizeof password - 1] = '\0';

		if (password[strlen(password) - 1] == '\n')
			password[strlen(password) - 1] = '\0';

		if (test_password(password, strlen(password), encrypted_file, compressed_size, crc32, decrypted_file) == 1)
			printf("Found possible password: %s\n", password);
	}

	free(encrypted_file);
	free(decrypted_file);
	fclose(dictFile);
	return 0;
}
