#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include <dirent.h>
#include <string.h>

#define BUF_SIZE 4096

//TODO: Function that decrypts/verifies the files found
//TODO: Function that moves the decrypted files to another directory and encrypts them with fishbowl key

struct node {
  char *data;
  struct node *next;
};

struct node *search_directory(const char *);
void add_element(struct node **, char *);
void traverse_list(struct node *);
gpgme_ctx_t decrypt_gpg(char *, char *, char *);
void error_msg(gpgme_error_t, char *);

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
    fprintf(stderr, "Could not open directory.");
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
      ctx = decrypt_gpg(ptr->data, "/usr/bin/gpg", "/home/lejonet/.gpg");
      verify_result = gpgme_op_verify_result(ctx);
      decrypt_result = gpgme_op_decrypt_result(ctx);
      ptr = ptr->next;
    }
  }
}

gpgme_ctx_t decrypt_gpg(char *file, char *binpath, char *homedir) {
  char buf[BUF_SIZE];
  //  FILE *fd_in, *fd_out;
  size_t read;
  gpgme_data_t ciphertext, plaintext;
  gpgme_ctx_t ctx;
  gpgme_error_t error;

  //  fd_in = fopen(file, "r");
  error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  if (error == GPG_ERR_NO_ERROR) {
    gpgme_new(&ctx);
    gpgme_set_armor(ctx, 1);
    printf("File: %s\n", file);
    error = gpgme_data_new_from_file(&ciphertext, file, 1);
    if (error == GPG_ERR_NO_ERROR) {
      error = gpgme_data_new(&plaintext);
      if (error == GPG_ERR_NO_ERROR) {
	error = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);
	if (error == GPG_ERR_NO_ERROR) {
	  //gpgme_data_release(ciphertext);
	  //error = gpgme_data_read(plaintext, buf, sizeof(buf), &read);
	  //if (error == GPG_ERR_NO_ERROR) {
	  // } else {
	  //  error_msg(error, "Gpgme_data_read(plaintext, buf, sizeof(buf), &read) failed: ");
	  // }
	} else {
	  error_msg(error, "Gpgme_op_decrypt_verify(ctx, ciphertext, plaintext) failed: ");
	}
      } else {
	error_msg(error, "Gpgme_data_new(&plaintext) failed: ");
      }
    } else {
      error_msg(error, "Gpgme_data_new_from_file(&ciphertext, file, 1) failed: ");
    }
  } else {
    error_msg(error, "Gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, binpath, homedir) failed: ");
  }
  //  fclose(fd_in);
  return ctx;
}

void error_msg(gpgme_error_t error, char *msg) {
  fprintf(stderr, "%s%s: %s\n", msg, gpgme_strsource(error), gpgme_strerror(error));
  exit(1);
}
