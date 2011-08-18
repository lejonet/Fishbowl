#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gpgme.h>
#include <dirent.h>
#include <string.h>

//TODO: Function that decrypts/verifies the files found
//TODO: Function that moves the decrypted files to another directory and encrypts them with fishbowl key

struct node {
  char *data;
  struct node *next;
};

struct node *search_directory(const char *);
void add_element(struct node **, char *);
void traverse_list(struct node *);
void decrypt_gpg(char *);
void error_msg(GpgmeError, char *);

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
  struct node *ptr = list;

  while (ptr != NULL) {
    if (ptr->data != NULL)
      printf("Data: %s\n", ptr->data);
      decrypt_gpg(ptr->data);
    ptr = ptr->next;
  }
}

void decrypt_gpg(char *file) {
  char buf[];
  FILE *fd_in, *fd_out;
  size_t read;
  GpgmeData ciphertext, plaintext;
  GpgmeCtx ctx;
  GpgmeError error;

  fd_in = fopen(file, "r");
  error = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP
  gpgme_new(&ctx);
  gpgme_set_armor(ctx, 1);
  error = gpgme_data_new_from_fd(&ciphertext, fd_in);
  if (error == GPGME_No_Error) {
    error = gpgme_data_new(&plaintext);
    if (error == GPGME_No_Error) {
      error = gpgme_op_decrypt(ctx, ciphertext, plaintext);
      if (error == GPGME_No_Error) {
	gpgme_data_release(ciphertext);
	error = gpgme_data_read(plaintext, buf, sizeof(buf), &read);
	if (error == GPGME_No_Error) {
	} else {
	  error_msg(error, "Gpgme_data_read(plaintext, buf, sizeof(buf), &read) failed: ");
	}
      } else {
	error_msg(error, "Gpgme_op_decrypt(ctx, ciphertext, plaintext) falied: ");
      }
    } else {
      error_msg(error, "Gpgme_data_new(&plaintext) failed: ");
    }
  } else {
    error_msg(error, "Gpgme_data_new_from_fd(&ciphertext, fd) failed: ");
  }
  fclose(fd_in);
}

void error_msg(GpgmeError error, char *msg) {
  fprintf(stderr, "%s%s\n", msg, error);
  exit(1);
}
