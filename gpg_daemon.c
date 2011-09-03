/*
 Fishbowl daemon - A small daemon to fetch, decrypt and verify, encrypt and move the files that arrives
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
// fail_if_err macro borrowed from the t-support.c file in the tests/gpg directory of the gpgme tarball
#define fail_if_error(error)					\
  do {								\
    if (error) {						\
          fprintf(stderr, "%s:%d: %s: %s\n",			\
                   __FILE__, __LINE__, gpgme_strsource (error),	\
		   gpgme_strerror (error));			\
          exit(1);						\
        }							\
  } while(0)							\


//TODO: Function that encrypts the files with the fishbowl key and then moves them to another directory

struct node {
  char *data;
  struct node *next;
};

struct gpg_data {
  gpgme_data_t plain, cipher;
  gpgme_ctx_t ctx;
};

struct node *search_directory(const char *);
void add_element(struct node **, char *);
void traverse_list(struct node *);
struct gpg_data *decrypt_gpg(char *, char *, char *);
void encrypt_gpg(struct gpg_data *, char *, char *);
void init_gpgme(gpgme_protocol_t, char *, char *);
void print_gpg_decrypt_data(gpgme_data_t);
void print_gpg_verify_data(gpgme_verify_result_t);
void print_gpg_sign_data(gpgme_sign_result_t);

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
  FILE *out;
  char *outfile = "./gpgtest/new_", *extension;
  int count = 1;
  struct gpg_data *gpg_outdata;
  struct node *ptr = list;
  gpgme_verify_result_t verify_result;
  gpgme_encrypt_result_t encrypt_result;
  gpgme_sign_result_t sign_result;

  while (ptr != NULL && ptr->data !=NULL) {
      printf("Data: %s\n", ptr->data);

      gpg_outdata = decrypt_gpg(ptr->data, "/usr/bin/gpg", ".gnupg");
      print_gpg_decrypt_data(gpg_outdata->plain);
      verify_result = gpgme_op_verify_result(gpg_outdata->ctx);
      print_gpg_verify_data(verify_result);

      encrypt_gpg(gpg_outdata, "/usr/bin/gpg", ".gnupg");
      encrypt_result = gpgme_op_encrypt_result(gpg_outdata->ctx);
      if (encrypt_result->invalid_recipients) {
	fprintf(stderr, "Invalid recipients detected: %s\n", encrypt_result->invalid_recipients->fpr);
	exit(1);
      }
      sign_result = gpgme_op_sign_result(gpg_outdata->ctx);
      print_gpg_sign_data(sign_result);
      sprintf(extension, "%d%s", count, ".gpg");
      strncat(outfile, extension, strlen(extension));
      printf("Outfile: %s\n", outfile);

      out = fopen(outfile, "wb");
      fwrite(gpg_outdata->cipher, sizeof(gpg_outdata->cipher), 1, out);
      fclose(out);
      count++;
      ptr = ptr->next;
  }
}


struct gpg_data *decrypt_gpg(char *file, char *binpath, char *homedir) {
  FILE *fd_in;
  gpgme_data_t ciphertext;
  gpgme_error_t error;
  struct gpg_data *outdata = malloc(sizeof(struct gpg_data));

  fd_in = fopen(file, "rb");
  init_gpgme(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  gpgme_new(&outdata->ctx);
  gpgme_set_armor(outdata->ctx, 1);
  //    printf("File: %s\n", file);
  error = gpgme_data_new_from_stream(&ciphertext, fd_in);
  fail_if_error(error);
  error = gpgme_data_new(&outdata->plain);
  fail_if_error(error);
  error = gpgme_op_decrypt_verify(outdata->ctx, ciphertext, outdata->plain);
  fail_if_error(error);
  gpgme_data_release(ciphertext);
  fclose(fd_in);
  
  return outdata;
}

void encrypt_gpg(struct gpg_data *indata, char *binpath, char *homedir) {
  gpgme_error_t error;
  gpgme_key_t recipient[2] = {NULL, NULL};

  init_gpgme(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  //  gpgme_new(&indata->ctx);
  //  gpgme_set_armor(indata->ctx, 1);
  error = gpgme_data_new(&indata->cipher);
  fail_if_error(error);
  error = gpgme_get_key(indata->ctx, "D09AFF79", &recipient[0], 0);
  fail_if_error(error);
  error = gpgme_op_encrypt_sign(indata->ctx, recipient, GPGME_ENCRYPT_ALWAYS_TRUST, indata->plain, indata->cipher);
  fail_if_error(error);
  gpgme_key_unref(recipient[0]);
}

// init_gpgme code borrowed from t-support.c in the tests/gpg directory of the gpgme tarball with some own additions
void init_gpgme (gpgme_protocol_t protocol, char *binpath, char *homedir) {
  gpgme_error_t error;

  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

  error = gpgme_engine_check_version(protocol);
  fail_if_error(error);
  error = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, binpath, homedir);
  fail_if_error(error);
}

// Code borrowed from the print_data function in t-support.h of the gpgme-tarball with some own additions
void print_gpg_decrypt_data(gpgme_data_t data) {
  char buf[BUF_SIZE+1];
  int res;

  res = gpgme_data_seek(data, 0, SEEK_SET);

  if (res) {
    fprintf(stderr, "Mayday! Mayday! Data search is going down! I repeat, data search is...*static noise*");
    fail_if_error(gpgme_err_code_from_errno(errno));
  }
  printf("Decrypted data: ");
  while ((res = gpgme_data_read(data, buf, BUF_SIZE)) > 0) {
    fwrite(buf, res, 1, stdout);
  }

  if (res < 0)
    fail_if_error(gpgme_err_code_from_errno(errno));
}

void print_gpg_verify_data(gpgme_verify_result_t data) {
  gpgme_signature_t signature;
  
  signature = data->signatures;
  printf("Fingerprint: %s\n", signature->fpr);
  printf("Status: %s\n", gpgme_strerror(signature->status));  
}

void print_gpg_sign_data(gpgme_sign_result_t data) {
  printf("Fingerprint: %s\n", data->signatures->fpr);
  printf("Hash algorithm: %i\n", data->signatures->hash_algo);
  printf("Pubkey algorithm: %i\n", data->signatures->pubkey_algo);
  printf("Type: %i\n", data->signatures->type);
}
