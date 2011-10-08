#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <gpgme.h>
#include <string.h>
#include <locale.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BIN "/usr/bin/gpg"
#define OUT "./TEST_OUT"
#define KEYID "D09AFF79"
#define CONFIG ".gnupg"

#define BUF_SIZE 4096
#define fail_if_error(error) do {						\
	if (error) {								\
		fprintf(stderr, "%s:%d: %s: %s\n",				\
				__FILE__, __LINE__, gpgme_strsource (error),	\
				gpgme_strerror (error));			\
		exit(EXIT_FAILURE);						\
	}									\
} while(0)

int armor = 1;
char *bin = BIN;
char *keyid = KEYID;
char *config = CONFIG;
gpgme_ctx_t ctx;

/*
 *
 */
void write_file (gpgme_data_t *data, char *file)
{
	FILE *fp;
	int count;
	char buf[BUF_SIZE];

	fp = fopen(file, "w");
	if (!fp) {
		perror("fopen failed");
		return;
	}

	while ((count = gpgme_data_read(*data, buf, BUF_SIZE))) {

		if (count == -1) {
			perror("gpgme_data_read failed");
			return;
		}

		fwrite(buf, 1, count, fp);
	}

	fclose(fp);
}

/*
 *
 */
gpgme_data_t *decrypt (char *file, gpgme_data_t *plain)
{
	FILE *fp;
	gpgme_data_t cipher;
	gpgme_error_t error;

	fp = fopen(file, "r");
	if (!fp) {
		perror("fopen failed");
		return NULL;
	}

	error = gpgme_data_new_from_stream(&cipher, fp);
	fail_if_error(error);

	error = gpgme_data_new(plain);
	fail_if_error(error);

	error = gpgme_op_decrypt_verify(ctx, cipher, *plain);
	fail_if_error(error);

	fclose(fp);
	gpgme_data_release(cipher);
	gpgme_data_seek(*plain, 0, SEEK_SET);

	return plain;
}

/*
 *
 */
gpgme_data_t *encrypt (gpgme_data_t *plain, gpgme_data_t *cipher)
{
	gpgme_error_t error;
	gpgme_key_t rcpt[2] = {NULL, NULL};

	error = gpgme_get_key(ctx, keyid, &rcpt[0], 0);
	fail_if_error(error);

	error = gpgme_data_new(cipher);
	fail_if_error(error);

	error = gpgme_op_encrypt_sign(ctx, rcpt, GPGME_ENCRYPT_ALWAYS_TRUST, *plain, *cipher);
	fail_if_error(error);

	gpgme_key_unref(rcpt[0]);
	gpgme_data_release(*plain);
	gpgme_data_seek(*cipher, 0, SEEK_SET);

	return cipher;
}

/*
 *
 */
void catch_a_fish (char *path, char* name)
{
	char fish[PATH_MAX];
	gpgme_data_t plain, cipher;

	snprintf(fish, PATH_MAX, "%s/%s", path, name);
	printf("New fish: %s\n", fish);

	decrypt(fish, &plain);
	encrypt(&plain, &cipher);

	snprintf(fish, PATH_MAX, OUT"/%s.gpg", name);
	write_file(&cipher, fish);
}

/*
 *
 */
void go_fishing (char *fishbowl)
{
	DIR *dirp;
	struct dirent *dentry;

	dirp = opendir(fishbowl);
	if (!dirp) {
		fprintf(stderr, "opendir failed: `%s'\n", fishbowl);
		return;
	}

	while ((dentry = readdir(dirp))) {

		if (dentry->d_type == DT_DIR)
			continue;

		catch_a_fish(fishbowl, dentry->d_name);
	}

	closedir(dirp);
}

/*
 *
 */
void init_fishbowl (void)
{
	gpgme_error_t error;

	mkdir(OUT, 0700);

	error = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	fail_if_error(error);

	error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, bin, config);
	fail_if_error(error);

	gpgme_check_version(NULL);
	setlocale(LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

	error = gpgme_new(&ctx);
	fail_if_error(error);

	gpgme_set_armor(ctx, armor);
}


/*
 *
 */
int main (void)
{
	init_fishbowl();

	go_fishing("./gpgtest");

	gpgme_release(ctx);

	return 0;
}

