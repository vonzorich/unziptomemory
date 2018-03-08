#pragma once

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

typedef struct {
	uch *inbuf;
	int inbufsiz;
	uch *outbuf;
	int outcnt;
	unsigned int bb;
	unsigned int bk;
	unsigned int inptr;
	// unsigned int hufts;
} zip_t;

void unzip(zip_t *pzip, char *path);
