/*
   Fishbowl daemon - A small daemon to fetch, decrypt, verify, encrypt, sign and move the files that arrives in a folder
   Copyright (C) 2011 Daniel Kuehn <daniel@kuehn.se>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA 
 */

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include <dirent.h>
#include <string.h>
#include <locale.h>
#include <errno.h>

#define BUF_SIZE 4096
#define fail_if_error(error) do {							\
		if (error) {								\
			fprintf(stderr, "%s:%d: %s: %s\n",				\
					__FILE__, __LINE__, gpgme_strsource (error),	\
					gpgme_strerror (error));			\
			exit(1);							\
		}									\
	} while(0)


typedef struct {
	void *next;
	char *path;
} fish_t;


int armor = 1;
gpgme_ctx_t ctx;
char *bin = "/usr/bin/gpg";
char *config = ".gnupg";


char *new_path (char *path, char *name)
{
	char *ptr;
	size_t size;

	size = strlen(path) + strlen(name) + 2;

	ptr = malloc(size);
	if (!ptr) {
		perror("malloc failed");
		return NULL;
	}

	snprintf(ptr, size, "%s/%s", path, name);
	return ptr;
}


fish_t *new_fish (char *path)
{
	fish_t *fish;

	fish = malloc(sizeof(fish_t));
	if (!fish) {
		perror("malloc failed\n");
		return NULL;
	}

	fish->next = NULL;
	fish->path = path;

	printf("DEBUG: %s\n", fish->path);
	return fish;
}


void print_gpg_decrypt_data(gpgme_data_t *data)
{
	char buf[BUF_SIZE+1];
	int res;

	res = gpgme_data_seek(*data, 0, SEEK_SET);

	if (res) {
		fprintf(stderr, "Mayday! Mayday! Data search is going down! I repeat, data search is...*static noise*");
		fail_if_error(gpgme_err_code_from_errno(errno));
	}
	printf("Decrypted data: ");
	while ((res = gpgme_data_read(*data, buf, BUF_SIZE)) > 0) {
		fwrite(buf, 1, res, stdout);
	}

	if (res < 0)
		fail_if_error(gpgme_err_code_from_errno(errno));
}


void print_gpg_verify_data(gpgme_verify_result_t data)
{
	gpgme_signature_t signature;

	signature = data->signatures;
	printf("Verification data: \n");
	printf("Fingerprint: %s\n", signature->fpr);
	printf("Status: %s\n", gpgme_strerror(signature->status));  
}


void print_gpg_sign_data(gpgme_sign_result_t data)
{
	printf("Signing data: \n");
	printf("Fingerprint: %s\n", data->signatures->fpr);
	printf("Hash algorithm: %i\n", data->signatures->hash_algo);
	printf("Pubkey algorithm: %i\n", data->signatures->pubkey_algo);
	printf("Type: %i Expected: %i\n", data->signatures->type, GPGME_SIG_MODE_NORMAL);
}


void write_file (gpgme_data_t *data, char *filename)
{
	FILE *fp;
	size_t count;
	char buf[BUF_SIZE];

	fp = fopen(filename, "w");
	if (!fp) {
		perror("fopen failed");
		return;
	}

	gpgme_data_seek(*data, 0, SEEK_SET);

	while ((count = gpgme_data_read(*data, buf, BUF_SIZE))) {

		if (count == -1) {
			perror("gpgme_data_read function failed");
			return;
		}

		fwrite(buf, 1, count, fp);
	}

	fclose(fp);
}


gpgme_data_t *decrypt (char *file)
{
	FILE *fp;
	gpgme_error_t error;
	gpgme_ctx_t ctx;
	gpgme_data_t *plain, cipher;
	gpgme_verify_result_t verify_result;

	fp = fopen(file, "r");
	if (!fp) {
		perror("fopen failed");
		return NULL;
	}

	plain = malloc(sizeof(gpgme_data_t));
	if (!plain) {
		perror("malloc failed");
		return NULL;
	}

	error = gpgme_new(&ctx);
	fail_if_error(error);

	gpgme_set_armor(ctx, armor);

	error = gpgme_data_new(plain);
	fail_if_error(error);

	error = gpgme_data_new_from_stream(&cipher, fp);
	fail_if_error(error);

	error = gpgme_op_decrypt_verify(ctx, cipher, *plain);
	fail_if_error(error);

	gpgme_data_release(cipher);
	fclose(fp);

	print_gpg_decrypt_data(plain);

	verify_result = gpgme_op_verify_result(ctx);
	print_gpg_verify_data(verify_result);

	return plain;
}


gpgme_data_t *encrypt (gpgme_data_t *plain)
{
	gpgme_ctx_t ctx;
	gpgme_error_t error;
	gpgme_data_t *cipher;
	gpgme_sign_result_t sign_result;
	gpgme_encrypt_result_t encrypt_result;
	gpgme_key_t recipient[2] = {NULL, NULL};

	cipher = malloc(sizeof(gpgme_data_t));
	if (!cipher) {
		perror("malloc failed");
		return NULL;
	}

	error = gpgme_new(&ctx);
	fail_if_error(error);

	gpgme_set_armor(ctx, armor);

	error = gpgme_data_new(cipher);
	fail_if_error(error);

	error = gpgme_get_key(ctx, "D09AFF79", &recipient[0], 0);
	fail_if_error(error);

	error = gpgme_op_encrypt_sign(ctx, recipient, GPGME_ENCRYPT_ALWAYS_TRUST, *plain, *cipher);
	fail_if_error(error);

	gpgme_key_unref(recipient[0]);

	encrypt_result = gpgme_op_encrypt_result(ctx);
	if (encrypt_result->invalid_recipients) {
		fprintf(stderr, "Invalid recipients detected: %s\n", encrypt_result->invalid_recipients->fpr);
		exit(1);
	}

	sign_result = gpgme_op_sign_result(ctx);
	print_gpg_sign_data(sign_result);
	return cipher;
}


fish_t *go_fishing (char *path)
{
	DIR *fp;
	char *ptr;
	fish_t *bowl, *fish;
	struct dirent *entry;

	bowl = fish = malloc(sizeof(fish_t));
	if (!bowl) {
		perror("malloc failed");
		return NULL;
	}

	fp = opendir(path);
	if (!fp) {
		free(bowl);
		fprintf(stderr, "opendir failed: `%s'\n", path);
		return NULL;
	}

	while ((entry = readdir(fp))) {

		if (entry->d_type == DT_DIR)
			continue;

		ptr = new_path(path, entry->d_name);
		printf("new fish: %s/%s\n", path, entry->d_name);
		fish = fish->next = new_fish(ptr);
	}

	closedir(fp);
	return bowl->next;
}


void gut_fishes (fish_t *fish)
{
	int count = 0;
	char path[PATH_MAX];
	gpgme_data_t *plain, *cipher;

	while (fish) {

		printf("Fish: %s\n", fish->path);

		plain = decrypt(fish->path);
		cipher = encrypt(plain);

		snprintf(path, PATH_MAX, "./TEST_OUT/new_%d.gpg", ++count);
		printf("Outfile: %s\n", path);
		write_file(cipher, path);

		gpgme_data_release(*plain);
		gpgme_data_release(*cipher);

		fish = fish->next;
	}
}


void init_fishbowl (void)
{
	gpgme_error_t error;

	error = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	fail_if_error(error);

	error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, bin, config);
	fail_if_error(error);

	gpgme_check_version(NULL);
	setlocale(LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
}


void clean_fishbowl (fish_t *fish)
{
	fish_t *tmp;

	while (fish) {

		tmp = fish->next;
		free(fish->path);
		free(fish);
		fish = tmp;
	}
}


int main (void)
{
	fish_t *bowl;

	init_fishbowl();

	bowl = go_fishing("./gpgtest");

	gut_fishes(bowl);

	clean_fishbowl(bowl);

	return 0;
}

