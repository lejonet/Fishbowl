#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <gpgme.h>
#include <string.h>
#include <locale.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>

/*
 * TODO
 * avoid crashes when opening invalid files
 * parse config file
 *   gpgdir = <folder>
 *   audit-log = <file>
 *   error-log = <file>
 *   fishbowl = <folder>
 *   leakbowl = <folder>
 *   fishbowl_id = <gpg id>
 *   leakbowl_id = <gpg id>
 * parse argv
 *   -b/--batch: just run once and shutdown
 *   (basically only calling pickup_fishes)
 *   -c/--config <file>
 *   -g/--gpgdir <folder>
 *   -v/--verbose
 *   -h/--help
 *   -a/--audit-log <file>
 *   -e/--error-log <file>
 *   -f/--fishbowl <folder>
 *   -l/--leakbowl <folder>
 *   -F/--fishbowl-id <gpg id>
 *   -L/--leakbowl-id <gpg id>
 */

#define BIN "/usr/bin/gpg"
#define KEYID "D09AFF79"
#define CONFIG ".gnupg"
#define FISHBOWL "./gpgtest"
#define LEAKBOWL "./leakbowl"
#define AUDIT_LOG "./fishbowl_audit.log"
#define ERROR_LOG "./fishbowl_error.log"

#define SIZE 4096
#define log_audit(...) _log(fp_audit, __VA_ARGS__)
#define log_error(...) _log(fp_error, __VA_ARGS__)
#define fail_if_error(error, ret)				\
do {								\
	if (error) {						\
		log_error("%s:%d: %s: %s\n",			\
				__FILE__, __LINE__,		\
				gpgme_strsource(error),		\
				gpgme_strerror(error));		\
		return (ret);					\
	}							\
} while(0)

int armor = 1;
char *bin = BIN;
char *keyid = KEYID;
char *config = CONFIG;
char *fishbowl = FISHBOWL;
char *leakbowl = LEAKBOWL;
char *audit_log = AUDIT_LOG;
char *error_log = ERROR_LOG;
FILE *fp_audit, *fp_error;

gpgme_ctx_t ctx;
unsigned int count = 0;

/*
 *
 */
void _log (FILE *fp, char *format, ...)
{
	va_list list;
	time_t tstamp;
	char buf[SIZE];

	time(&tstamp);
	strftime(buf, SIZE, "%Y%m%d %H:%M:%S", localtime(&tstamp));
	fprintf(fp, "%s ", buf);

	va_start(list, format);
	vfprintf(fp, format, list);
	va_end(list);
	fflush(fp);
}

/*
 *
 */
void write_file (gpgme_data_t *data, char *file)
{
	FILE *fp;
	int count;
	char buf[SIZE];

	fp = fopen(file, "w");
	if (!fp) {
		log_error("fopen failed: `%s'\n", file);
		return;
	}

	while ((count = gpgme_data_read(*data, buf, SIZE))) {

		if (count == -1) {
			log_error("gpgme_data_read failed");
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
		log_error("fopen failed: `%s'\n", file);
		return NULL;
	}

	error = gpgme_data_new_from_stream(&cipher, fp);
	fail_if_error(error, NULL);

	error = gpgme_data_new(plain);
	fail_if_error(error, NULL);

	error = gpgme_op_decrypt_verify(ctx, cipher, *plain);
	fail_if_error(error, NULL);

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
	fail_if_error(error, NULL);

	error = gpgme_data_new(cipher);
	fail_if_error(error, NULL);

	error = gpgme_op_encrypt_sign(ctx, rcpt, GPGME_ENCRYPT_ALWAYS_TRUST, *plain, *cipher);
	fail_if_error(error, NULL);

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
	log_audit("New!   fish number %u: `%s'\n", ++count, fish);

	decrypt(fish, &plain);
	encrypt(&plain, &cipher);

	snprintf(fish, PATH_MAX, "%s/%s.gpg", leakbowl, name);
	write_file(&cipher, fish);
	log_audit("Moved! fish number %u: `%s'\n", count, fish);
}

/*
 *
 */
void pickup_fishes (char *fishbowl)
{
	DIR *dirp;
	struct dirent *dentry;

	dirp = opendir(fishbowl);
	if (!dirp) {
		log_error("opendir failed: `%s'\n", fishbowl);
		return;
	}

	while ((dentry = readdir(dirp))) {

		if (dentry->d_type != DT_REG)
			continue;

		catch_a_fish(fishbowl, dentry->d_name);
	}

	closedir(dirp);
}

/*
 *
 */
void go_fishing (char *fishbowl)
{
	int fd, ret;
	char buf[SIZE];
	struct inotify_event *event;

	pickup_fishes(fishbowl);

	fd = inotify_init();
	if (fd < 0) {
		log_error("inotify_init failed\n");
		return;
	}

	ret = inotify_add_watch(fd, fishbowl, IN_CLOSE_WRITE|IN_MOVED_TO);
	if (ret < 0) {
		log_error("inotify_add_watch failed: `%s'\n", fishbowl);
		return;
	}

	do {
		memset(buf, 0, SIZE);
		ret = read(fd, buf, SIZE);
		if (ret < 1) {
			log_audit("end of read, quitting\n");
			break;
		}

		event = (struct inotify_event *)buf;
		catch_a_fish(fishbowl, event->name);

	} while (1);

	close(fd);
}

/*
 *
 */
int init_fishbowl (void)
{
	int ret;
	gpgme_error_t error;

	ret = mkdir(leakbowl, 0700);

	fp_audit = fopen(audit_log, "a");
	if (!fp_audit) {
		log_error("fopen failed: `%s'\n", audit_log);
		return 0;
	}
		
	fp_error = fopen(error_log, "a");
	if (!fp_error) {
		log_error("fopen failed: `%s'\n", error_log);
		return 0;
	}

	error = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	fail_if_error(error, 0);

	error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, bin, config);
	fail_if_error(error, 0);

	gpgme_check_version(NULL);
	setlocale(LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

	error = gpgme_new(&ctx);
	fail_if_error(error, 0);

	gpgme_set_armor(ctx, armor);

	return 1;
}

/*
 *
 */
void cleanup_fishbowl (void)
{
	gpgme_release(ctx);
	fclose(fp_audit);
	fclose(fp_error);
}

/*
 *
 */
int main (void)
{
	if (!init_fishbowl()) {
		fprintf(stderr, "initialization failed, quitting\n");
		exit(EXIT_FAILURE);
	}

	printf("going dark...\n");

	daemon(1, 0);

	go_fishing(fishbowl);

	cleanup_fishbowl();

	return 0;
}
