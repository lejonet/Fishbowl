#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include <dirent.h>
#include <string.h>
#include <locale.h>

#define BUF_SIZE 4096
// fail_if_err macro borrowed from the t-support.c file in the tests/gpg directory of the gpgme tarball
#define fail_if_err(error)					\
  do								\
    {								\
      if (error)						\
        {							\
          fprintf (stderr, "%s:%d: %s: %s\n",			\
                   __FILE__, __LINE__, gpgme_strsource (error),	\
		   gpgme_strerror (error));			\
          exit (1);						\
        }							\
    }								\
  while (0)

//TODO: Function that encrypts the files with the fishbowl key and then moves them to another directory

struct node {
  char *data;
  struct node *next;
};

struct node *search_directory(const char *);
void add_element(struct node **, char *);
void traverse_list(struct node *);
gpgme_ctx_t decrypt_gpg(char *, char *, char *);
void init_gpgme(gpgme_protocol_t);
gpgme_error_t passphrase_cb(void *, const char *, const char *, int, int);
//void error_msg(gpgme_error_t, char *);

int main(void) {
  struct node *ptr;
  //  int array_size, i;
  ptr = search_directory("./gpgtest");
  traverse_list(ptr);
  //  array_size = sizeof(ptr) / sizeof(*ptr);
  //  for(i = 0; i < (array_size-1); i++)
  //    printf("File: %s\n", filelist[i]);

  return 0;
}

struct node *search_directory(const char *dir) {
  DIR *dir_fd;
  struct node *ptr = malloc(sizeof(struct node));
  struct dirent *fileinfo;

  dir_fd = opendir(dir);
  if (dir_fd != NULL) {
    while (fileinfo = readdir(dir_fd)) 
      add_element(&ptr, fileinfo->d_name);
    closedir(dir_fd);
  } else {
    fprintf(stderr, "Could not open directory: %s.", dir);
  }
  return ptr;
}

void add_element(struct node **list, char *element) {
  struct node *ptr = *list, *newnode;
  char cwd[PATH_MAX+1];
  char *full_path;

  getcwd(cwd, PATH_MAX+1);
  //  printf("cwd: %s\n", cwd);
  if (!strncmp(".", element, strlen(element)) || !strncmp("..", element, strlen(element)))
    return;
  full_path = malloc(strlen(cwd) + strlen(element) + 3);
  newnode = malloc(sizeof(struct node));
  sprintf(full_path, "%s/%s", cwd, element);
  //  printf("Path: %s\n", full_path);
  newnode->data = full_path;
  newnode->next = *list;
  *list = newnode;
  //  printf("Data: %s\n", newnode->data);
}

void traverse_list(struct node *list) {
  gpgme_ctx_t ctx;
  gpgme_verify_result_t verify_result;
  gpgme_decrypt_result_t decrypt_result;
  struct node *ptr = list;

  while (ptr != NULL) {
    if (ptr->data != NULL) {
      printf("Data: %s\n", ptr->data);
      ctx = decrypt_gpg(ptr->data, "/usr/bin/gpg", "/home/lejonet/.gnupg");
      verify_result = gpgme_op_verify_result(ctx);
      decrypt_result = gpgme_op_decrypt_result(ctx);
      ptr = ptr->next;
    }
  }
}

gpgme_ctx_t decrypt_gpg(char *file, char *binpath, char *homedir) {
  char buf[BUF_SIZE];
  FILE *fd_in;
  size_t read;
  gpgme_data_t ciphertext, plaintext;
  gpgme_ctx_t ctx;
  gpgme_error_t error;

  fd_in = fopen(file, "r");
  //  error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  //  if (error == GPG_ERR_NO_ERROR) {
  init_gpgme(GPGME_PROTOCOL_OpenPGP);
  gpgme_new(&ctx);
  gpgme_set_armor(ctx, 1);
  //    printf("File: %s\n", file);
  error = gpgme_data_new_from_stream(&ciphertext, fd_in);
  fail_if_err(error);
  error = gpgme_data_new(&plaintext);
  fail_if_err(error);
  error = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);
  fail_if_err(error);
  //gpgme_data_release(ciphertext);
  //error = gpgme_data_read(plaintext, buf, sizeof(buf), &read);
  //fail_if_err(error)
  // } else {
  //  error_msg(error, "Gpgme_data_read(plaintext, buf, sizeof(buf), &read) failed: ");
  // }
  gpgme_data_release(ciphertext);
  gpgme_data_release(plaintext);
  gpgme_release(ctx);
  fclose(fd_in);
  
  return ctx;
  }

    //void error_msg(gpgme_error_t error, char *msg) {
    //  fprintf(stderr, "%s%s: %s\n", msg, gpgme_strsource(error), gpgme_strerror(error));
    //  exit(1);
    //}

// init_gpgme code borrowed from t-support.c in the tests/gpg directory of the gpgme tarball
void init_gpgme (gpgme_protocol_t protocol) {
  gpgme_error_t error;

  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

  error = gpgme_engine_check_version (protocol);
  fail_if_err (error);
}

gpgme_error_t passphrase_cb(void *opaque, const char *uid_hint, const char *passphrase_info, int last_was_bad, int fd) {
  char *password = "" ;
  int res, offset = 0, passlength = strlen(password);

  do {
    res = write(fd, &password[offset], passlength-offset);
    if (res > 0)
      offset += res;
  } while ( res > 0 && res != passlength);

  if (res == passlength) {
    return 0;
  } else {
    return 1;
  }
}
