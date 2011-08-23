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
gpgme_data_t decrypt_gpg(char *, char *, char *);
void init_gpgme(gpgme_protocol_t, char *, char *);
gpgme_error_t passphrase_cb(void *, const char *, const char *, int, int);
void print_gpg_data(gpgme_data_t);

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
  sprintf(full_path, "%s/gpgtest/%s", cwd, element);
  //  printf("Path: %s\n", full_path);
  newnode->data = full_path;
  newnode->next = *list;
  *list = newnode;
  //  printf("Data: %s\n", newnode->data);
}

void traverse_list(struct node *list) {
  gpgme_data_t gpg_data;
  struct node *ptr = list;

  while (ptr != NULL && ptr->data !=NULL) {
      printf("Data: %s\n", ptr->data);
      gpg_data = decrypt_gpg(ptr->data, "/usr/bin/gpg", ".gnupg");
      print_gpg_data(gpg_data);
      ptr = ptr->next;
  }
}

gpgme_data_t decrypt_gpg(char *file, char *binpath, char *homedir) {
  FILE *fd_in;
  size_t read;
  gpgme_data_t ciphertext, plaintext;
  gpgme_ctx_t ctx;
  gpgme_error_t error;

  fd_in = fopen(file, "rb");
  init_gpgme(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  gpgme_new(&ctx);
  gpgme_set_armor(ctx, 1);
  gpgme_set_passphrase_cb(ctx, passphrase_cb, NULL);
  //    printf("File: %s\n", file);
  error = gpgme_data_new_from_stream(&ciphertext, fd_in);
  fail_if_err(error);
  error = gpgme_data_new(&plaintext);
  fail_if_err(error);
  error = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);
  fail_if_err(error);
  gpgme_data_release(ciphertext);
  gpgme_release(ctx);
  fclose(fd_in);
  
  return plaintext;
  }

// init_gpgme code borrowed from t-support.c in the tests/gpg directory of the gpgme tarball
void init_gpgme (gpgme_protocol_t protocol, char *binpath, char *homedir) {
  gpgme_error_t error;

  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

  error = gpgme_engine_check_version(protocol);
  fail_if_err(error);
  error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  fail_if_err(error);
}

gpgme_error_t passphrase_cb(void *opaque, const char *uid_hint, const char *passphrase_info, int last_was_bad, int fd) {
  char *password = "" ;
  int res, offset = 0, passlength = strlen(password);
  
  printf("Password: %s", password);
  printf("Passlength: %d\n", passlength);
  do {
    res = write(fd, &password[offset], passlength-offset);
    printf("res: %d\n", res);
    if (res > 0) {
      offset += res;
      printf("offset: %d\n", offset);
    }
  } while ( res > 0 && res != passlength);

  if (res == passlength) {
    return 0;
  } else {
    return gpgme_err_code_from_errno(errno);
  }
}

void print_gpg_data(gpgme_data_t data) {
  char buf[BUF_SIZE+1];
  int res;

  res = gpgme_data_seek(data, 0, SEEK_SET);

  if (res) {
    fprintf(stderr, "Mayday! Mayday! Printing is going down! I repeat, printing is...*static noise*");
    fail_if_err(gpgme_err_code_from_errno(errno));
  }
  
  while ((res = gpgme_data_read(data, buf, BUF_SIZE)) > 0) {
    fwrite(buf, res, 1, stdout);
  }

  if (res < 0)
    fail_if_err(gpgme_err_code_from_errno(errno));
}
