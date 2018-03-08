/*
gcc -D_GNU_SOURCE *.c
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "inflate.h"

int load_zip_file(char *path);

static unsigned char *start = NULL;
static int zipfilelength;

int main(int argc, char *argv[])
{
	if (2 <= argc) {
		zip_t  zip;
		if (0 > load_zip_file(argv[1])) {
			fprintf(stderr, "load zip file %s failed\n", argv[1]);
		}
		bzero(&zip, sizeof(zip_t));
		zip.inbuf = start;
		zip.inbufsiz = zipfilelength;
		if (2 == argc) {
			unzip(&zip, NULL);
		}
		else if (3 == argc) {
			unzip(&zip, argv[2]);
			fprintf(stdout, "bb=%d\n", zip.bb);
			fprintf(stdout, "bk=%d\n", zip.bk);
			fprintf(stdout, "inptr=%d\n", zip.inptr);
			fprintf(stdout, "outcnt=%d\n", zip.outcnt);
			zip.outbuf = malloc(zip.outcnt);
			unzip(&zip, argv[2]);
			fprintf(stdout, "%.*s\n", zip.outcnt, zip.outbuf);
			fprintf(stdout, "outcnt=%d\n", zip.outcnt);
		}
	}
    return 0;
}
int load_zip_file(char *path)
{
	int fd = -1;
	struct stat f_stat;

	if ((fd = open(path, O_RDONLY)) == -1)
		return -1;
	if (fstat(fd, &f_stat))
		return -1;

	zipfilelength = (int)f_stat.st_size;
	start = mmap(start, zipfilelength, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == start)
		return -1;
	close(fd);
	return 0;
}