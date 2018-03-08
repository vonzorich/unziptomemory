/*
derived from gzip source code by Antoine Von Zorich

inflate.c -- Not copyrighted 1992 by Mark Adler
version c10p1, 10 January 1993 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "inflate.h"

enum zip_hdr_offset_enum {
	LOCAL_FILE_HDR_SIGNATURE,
	ZIP_VERSION_OFFSET = 4,
	ZIP_FLAG_OFFSET = 6,
	ZIP_METHOD_OFFSET = 8,
	ZIP_TIME_OFFSET = 10,
	ZIP_DATE_OFFSET = 12,
	ZIP_CRC32_OFFSET = 14,
	ZIP_COMPRESSED_SIZE_OFFSET = 18,
	ZIP_UNCOMPRESSED_SIZE_OFFSET = 22,
	ZIP_FILENAME_LENGTH_OFFSET = 26,
	ZIP_EXTRA_FIELD_LENGTH_OFFSET = 28,
	ZIP_FILENAME_OFFSET = 30
};

struct huft {
	uch e;                /* number of extra bits or operation */
	uch b;                /* number of bits in this code or subcode */
	union {
		ush n;              /* literal, length base, or distance base */
		struct huft *t;     /* pointer to next level of table */
	} v;
};

/* Tables for deflate from PKZIP's appnote.txt. */
static unsigned border[] = {    /* Order of the bit length code lengths */
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
static ush cplens[] = {         /* Copy lengths for literal codes 257..285 */
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0 };
/* note: see note #13 above about the 258 in this list. */
static ush cplext[] = {         /* Extra bits for literal codes 257..285 */
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 99, 99 }; /* 99==invalid */
static ush cpdist[] = {         /* Copy offsets for distance codes 0..29 */
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
	8193, 12289, 16385, 24577 };
static ush cpdext[] = {         /* Extra bits for distance codes */
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
	12, 12, 13, 13 };

ush mask_bits[] = {
	0x0000,
	0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
	0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
};

int lbits = 9;          /* bits in base literal/length lookup table */
int dbits = 6;          /* bits in base distance lookup table */
						/* If BMAX needs to be larger than 16, then h and x[] should be ulg. */
#define BMAX 16         /* maximum bit length of any code (16 for explode) */
#define N_MAX 288       /* maximum number of codes in any set */

#define NEXTBYTE()  (uch)get_byte()
#define NEEDBITS(n) {while(k<(n)){b|=((ulg)NEXTBYTE())<<k;k+=8;}}
#define DUMPBITS(n) {b>>=(n);k-=(n);}
#define get_byte()  pzip->inbuf[pzip->inptr++]

int huft_free(struct huft *t)
/* t: table to free */
/* Free the malloc'ed tables built by huft_build(), which makes a linked
list of the tables it made, with the links in a dummy first entry of
each table. */
{
	register struct huft *p, *q;
	/* Go through linked list, freeing from the malloced (t[-1]) address. */
	p = t;
	while (p != (struct huft *)NULL)
	{
		q = (--p)->v.t;
		free((char*)p);
		p = q;
	}
	return 0;
}

int huft_build(b, n, s, d, e, t, m)
unsigned *b;            /* code lengths in bits (all assumed <= BMAX) */
unsigned n;             /* number of codes (assumed <= N_MAX) */
unsigned s;             /* number of simple-valued codes (0..s-1) */
ush *d;                 /* list of base values for non-simple codes */
ush *e;                 /* list of extra bits for non-simple codes */
struct huft **t;        /* result: starting table */
int *m;                 /* maximum lookup bits, returns actual */
						/* Given a list of code lengths and a maximum table size, make a set of
						tables to decode that set of codes.  Return zero on success, one if
						the given code set is incomplete (the tables are still built in this
						case), two if the input is invalid (all zero length codes or an
						oversubscribed set of lengths), and three if not enough memory. */
{
	unsigned a;                   /* counter for codes of length k */
	unsigned c[BMAX + 1];           /* bit length count table */
	unsigned f;                   /* i repeats in table every f entries */
	int g;                        /* maximum code length */
	int h;                        /* table level */
	register unsigned i;          /* counter, current code */
	register unsigned j;          /* counter */
	register int k;               /* number of bits in current code */
	int l;                        /* bits per table (returned in m) */
	register unsigned *p;         /* pointer into c[], b[], or v[] */
	register struct huft *q;      /* points to current table */
	struct huft r;                /* table entry for structure assignment */
	struct huft *u[BMAX];         /* table stack */
	unsigned v[N_MAX];            /* values in order of bit length */
	register int w;               /* bits before this table == (l * h) */
	unsigned x[BMAX + 1];           /* bit offsets, then code stack */
	unsigned *xp;                 /* pointer into x */
	int y;                        /* number of dummy codes added */
	unsigned z;                   /* number of entries in current table */

								  /* Generate counts for each bit length */
	bzero(c, sizeof(c));
	p = b;  i = n;
	do {
		c[*p]++;                    /* assume all entries <= BMAX */
		p++;                      /* Can't combine with above line (Solaris bug) */
	} while (--i);
	if (c[0] == n)                /* null input--all zero length codes */
	{
		*t = (struct huft *)NULL;
		*m = 0;
		return 0;
	}

	/* Find minimum and maximum length, bound *m by those */
	l = *m;
	for (j = 1; j <= BMAX; j++)
		if (c[j])
			break;
	k = j;                        /* minimum code length */
	if ((unsigned)l < j)
		l = j;
	for (i = BMAX; i; i--)
		if (c[i])
			break;
	g = i;                        /* maximum code length */
	if ((unsigned)l > i)
		l = i;
	*m = l;

	/* Adjust last length count to fill out codes, if needed */
	for (y = 1 << j; j < i; j++, y <<= 1)
		if ((y -= c[j]) < 0)
			return 2;                 /* bad input: more codes than bits */
	if ((y -= c[i]) < 0)
		return 2;
	c[i] += y;

	/* Generate starting offsets into the value table for each length */
	x[1] = j = 0;
	p = c + 1;  xp = x + 2;
	while (--i) {                 /* note that i == g from above */
		*xp++ = (j += *p++);
	}

	/* Make a table of values in order of bit lengths */
	p = b;  i = 0;
	do {
		if ((j = *p++) != 0)
			v[x[j]++] = i;
	} while (++i < n);

	/* Generate the Huffman codes and for each, make the table entries */
	x[0] = i = 0;                 /* first Huffman code is zero */
	p = v;                        /* grab values in bit order */
	h = -1;                       /* no tables yet--level -1 */
	w = -l;                       /* bits decoded == (l * h) */
	u[0] = (struct huft *)NULL;   /* just to keep compilers happy */
	q = (struct huft *)NULL;      /* ditto */
	z = 0;                        /* ditto */

								  /* go through the bit lengths (k already is bits in shortest code) */
	for (; k <= g; k++)
	{
		a = c[k];
		while (a--)
		{
			/* here i is the Huffman code of length k bits for value *p */
			/* make tables up to required level */
			while (k > w + l)
			{
				h++;
				w += l;                 /* previous table always l bits */

										/* compute minimum size table less than or equal to l bits */
				z = (z = g - w) > (unsigned)l ? l : z;  /* upper limit on table size */
				if ((f = 1 << (j = k - w)) > a + 1)     /* try a k-w bit table */
				{                       /* too few codes for k-w bit table */
					f -= a + 1;           /* deduct codes from patterns left */
					xp = c + k;
					while (++j < z)       /* try smaller tables up to z bits */
					{
						if ((f <<= 1) <= *++xp)
							break;            /* enough codes to use up j bits */
						f -= *xp;           /* else deduct codes from patterns */
					}
				}
				z = 1 << j;             /* table entries for j-bit table */

										/* allocate and link in new table */
				if ((q = (struct huft *)malloc((z + 1) * sizeof(struct huft))) ==
					(struct huft *)NULL)
				{
					if (h)
						huft_free(u[0]);
					return 3;             /* not enough memory */
				}
				// hufts += z + 1;         /* track memory usage */
				*t = q + 1;             /* link to list for huft_free() */
				*(t = &(q->v.t)) = (struct huft *)NULL;
				u[h] = ++q;             /* table starts after link */

										/* connect to last table, if there is one */
				if (h)
				{
					x[h] = i;             /* save pattern for backing up */
					r.b = (uch)l;         /* bits to dump before this table */
					r.e = (uch)(16 + j);  /* bits in this table */
					r.v.t = q;            /* pointer to this table */
					j = i >> (w - l);     /* (get around Turbo C bug) */
					u[h - 1][j] = r;        /* connect to last table */
				}
			}

			/* set up table entry in r */
			r.b = (uch)(k - w);
			if (p >= v + n)
				r.e = 99;               /* out of values--invalid code */
			else if (*p < s)
			{
				r.e = (uch)(*p < 256 ? 16 : 15);    /* 256 is end-of-block code */
				r.v.n = (ush)(*p);             /* simple code is just the value */
				p++;                           /* one compiler does not like *p++ */
			}
			else
			{
				r.e = (uch)e[*p - s];   /* non-simple--look up in lists */
				r.v.n = d[*p++ - s];
			}

			/* fill code-like entries with r */
			f = 1 << (k - w);
			for (j = i >> w; j < z; j += f)
				q[j] = r;

			/* backwards increment the k-bit code i */
			for (j = 1 << (k - 1); i & j; j >>= 1)
				i ^= j;
			i ^= j;

			/* backup over finished tables */
			while ((i & ((1 << w) - 1)) != x[h])
			{
				h--;                    /* don't need to update q */
				w -= l;
			}
		}
	}
	/* Return true (1) if we were given an incomplete table */
	return y != 0 && g != 1;
}

int inflate_codes(pzip, tl, td, bl, bd)
zip_t *pzip;
struct huft *tl, *td;   /* literal/length and distance decoder tables */
int bl, bd;             /* number of bits decoded by tl[] and td[] */
/* inflate (decompress) the codes in a deflated (compressed) block.
   Return an error code or zero if it all goes ok. */
{
  register unsigned e;  /* table entry flag/number of extra bits */
  unsigned n;        /* length and index for copy */
  unsigned d;
  struct huft *t;       /* pointer to table entry */
  unsigned ml, md;      /* masks for bl and bd bits */
  register ulg b;       /* bit buffer */
  register unsigned k;  /* number of bits in bit buffer */

  /* make local copies of globals */
  b = pzip->bb;                       /* initialize bit buffer */
  k = pzip->bk;
  /* inflate the coded data */
  ml = mask_bits[bl];           /* precompute masks for speed */
  md = mask_bits[bd];
  for (;;)                      /* do until end of block */
  {
    NEEDBITS((unsigned)bl)
    if ((e = (t = tl + ((unsigned)b & ml))->e) > 16)
      do {
        if (e == 99)
          return 1;
        DUMPBITS(t->b)
        e -= 16;
        NEEDBITS(e)
      } while ((e = (t = t->v.t + ((unsigned)b & mask_bits[e]))->e) > 16);
    DUMPBITS(t->b)
    if (e == 16)                /* then it's a literal */
    {
		if (pzip->outbuf) {
			pzip->outbuf[pzip->outcnt++] = (uch)t->v.n;
		}
		else {
			pzip->outcnt++;
		}
    }
    else                        /* it's an EOB or a length */
    {
      /* exit if end of block */
      if (e == 15)
        break;

      /* get length of block to copy */
      NEEDBITS(e)
      n = t->v.n + ((unsigned)b & mask_bits[e]);
      DUMPBITS(e);

      /* decode distance of block to copy */
      NEEDBITS((unsigned)bd)
      if ((e = (t = td + ((unsigned)b & md))->e) > 16)
        do {
          if (e == 99)
            return 1;
          DUMPBITS(t->b)
          e -= 16;
          NEEDBITS(e)
        } while ((e = (t = t->v.t + ((unsigned)b & mask_bits[e]))->e) > 16);
      DUMPBITS(t->b)
      NEEDBITS(e)
      d = t->v.n + ((unsigned)b & mask_bits[e]);
	  DUMPBITS(e);

	  while (n--) {
		  if (pzip->outbuf) {
			  pzip->outbuf[pzip->outcnt] = pzip->outbuf[pzip->outcnt - d];
		  }
		  pzip->outcnt++;
	  }
    }
  }

  /* restore the globals from the locals */
  pzip->bb = b;                       /* restore global bit buffer */
  pzip->bk = k;
  /* done */
  return 0;
}

int inflate_dynamic(zip_t *pzip)
/* decompress an inflated type 2 (dynamic Huffman codes) block. */
{
  int i;                /* temporary variables */
  unsigned j;
  unsigned l;           /* last length */
  unsigned m;           /* mask for bit lengths table */
  unsigned n;           /* number of lengths to get */
  struct huft *tl;      /* literal/length code table */
  struct huft *td;      /* distance code table */
  int bl;               /* lookup bits for tl */
  int bd;               /* lookup bits for td */
  unsigned nb;          /* number of bit length codes */
  unsigned nl;          /* number of literal/length codes */
  unsigned nd;          /* number of distance codes */
  unsigned ll[286+30];  /* literal/length and distance code lengths */
  register ulg b;       /* bit buffer */
  register unsigned k;  /* number of bits in bit buffer */

  /* make local bit buffer */
  b = pzip->bb;
  k = pzip->bk;

  /* read in table lengths */
  NEEDBITS(5)
  nl = 257 + ((unsigned)b & 0x1f);      /* number of literal/length codes */
  DUMPBITS(5)
  NEEDBITS(5)
  nd = 1 + ((unsigned)b & 0x1f);        /* number of distance codes */
  DUMPBITS(5)
  NEEDBITS(4)
  nb = 4 + ((unsigned)b & 0xf);         /* number of bit length codes */
  DUMPBITS(4)
  if (nl > 286 || nd > 30)
    return 1;                   /* bad lengths */

  /* read in bit-length-code lengths */
  for (j = 0; j < nb; j++)
  {
    NEEDBITS(3)
    ll[border[j]] = (unsigned)b & 7;
    DUMPBITS(3)
  }
  for (; j < 19; j++)
    ll[border[j]] = 0;

  /* build decoding table for trees--single level, 7 bit lookup */
  bl = 7;
  if ((i = huft_build(ll, 19, 19, NULL, NULL, &tl, &bl)) != 0)
  {
    if (i == 1)
      huft_free(tl);
    return i;                   /* incomplete code set */
  }

  /* read in literal and distance code lengths */
  n = nl + nd;
  m = mask_bits[bl];
  i = l = 0;
  while ((unsigned)i < n)
  {
    NEEDBITS((unsigned)bl)
    j = (td = tl + ((unsigned)b & m))->b;
    DUMPBITS(j)
    j = td->v.n;
    if (j < 16)                 /* length of code in bits (0..15) */
      ll[i++] = l = j;          /* save last length in l */
    else if (j == 16)           /* repeat last length 3 to 6 times */
    {
      NEEDBITS(2)
      j = 3 + ((unsigned)b & 3);
      DUMPBITS(2)
      if ((unsigned)i + j > n)
        return 1;
      while (j--)
        ll[i++] = l;
    }
    else if (j == 17)           /* 3 to 10 zero length codes */
    {
      NEEDBITS(3)
      j = 3 + ((unsigned)b & 7);
      DUMPBITS(3)
      if ((unsigned)i + j > n)
        return 1;
      while (j--)
        ll[i++] = 0;
      l = 0;
    }
    else                        /* j == 18: 11 to 138 zero length codes */
    {
      NEEDBITS(7)
      j = 11 + ((unsigned)b & 0x7f);
      DUMPBITS(7)
      if ((unsigned)i + j > n)
        return 1;
      while (j--)
        ll[i++] = 0;
      l = 0;
    }
  }

  /* free decoding table for trees */
  huft_free(tl);

  /* restore the global bit buffer */
  pzip->bb = b;
  pzip->bk = k;

  /* build the decoding tables for literal/length and distance codes */
  bl = lbits;
  if ((i = huft_build(ll, nl, 257, cplens, cplext, &tl, &bl)) != 0)
  {
    if (i == 1) {
      fprintf(stderr, " incomplete literal tree\n");
      huft_free(tl);
    }
    return i;                   /* incomplete code set */
  }
  bd = dbits;
  if ((i = huft_build(ll + nl, nd, 0, cpdist, cpdext, &td, &bd)) != 0)
  {
    if (i == 1) {
      fprintf(stderr, " incomplete distance tree\n");
#ifdef PKZIP_BUG_WORKAROUND
      i = 0;
    }
#else
      huft_free(td);
    }
    huft_free(tl);
    return i;                   /* incomplete code set */
#endif
  }

  /* decompress until an end-of-block code */
  if (inflate_codes(pzip, tl, td, bl, bd))
    return 1;

  /* free the decoding tables, return */
  huft_free(tl);
  huft_free(td);
  return 0;
}

int inflate_block(zip_t *pzip, int *e)
{
  unsigned t;           /* block type */
  register ulg b;       /* bit buffer */
  register unsigned k;  /* number of bits in bit buffer */

  /* make local bit buffer */
  b = pzip->bb;
  k = pzip->bk;

  /* read in last block bit */
  NEEDBITS(1)
  *e = (int)b & 1;
  DUMPBITS(1)

  /* read in block type */
  NEEDBITS(2)
  t = (unsigned)b & 3;
  DUMPBITS(2)

  /* restore the global bit buffer */
  pzip->bb = b;
  pzip->bk = k;

  /* inflate that block type */
  if (t == 2)
    return inflate_dynamic(pzip);

  /* bad block type */
  return 2;
}

int inflate(zip_t *pzip)
{
	int e;                /* last block flag */
	int r;                /* result code */
	// unsigned h;           /* maximum struct huft's malloc'ed */

	pzip->bb = 0;
	pzip->bk = 0;
	pzip->outcnt = 0;
						  /* initialize window, bit buffer */
	/* decompress until the last block */
	// h = 0;
	do {
		// pzip->hufts = 0;
		if ((r = inflate_block(pzip, &e)) != 0)
			return r;
		/*
		if (pzip->hufts > h)
			h = pzip->hufts;
		*/
	} while (!e);

	return 0;
}

void unzip(zip_t *pzip, char *path)
{
	unsigned char zipsignature[] = { 0x50, 0x4b, 3, 4 };
	uch *p = NULL, *beg;
	uch *ptop;
	int siz = pzip->inbufsiz;
	int pathlen = path ? strlen(path) : 0;
	beg = pzip->inbuf;
	ptop = beg + siz;
	while (NULL != (p = (uch *)memmem(beg, siz, zipsignature, 4))) {
		int filenamlen;
		unsigned char *pos;
		pos = p + ZIP_FILENAME_LENGTH_OFFSET;
		filenamlen = pos[0] | (pos[1] << 8);
		pos += ZIP_FILENAME_OFFSET - ZIP_FILENAME_LENGTH_OFFSET;
		if (NULL == path) {
			printf("<%.*s>\n", filenamlen, pos);
		} else if (pathlen == filenamlen && !strncmp(path, (char *)pos, filenamlen)) {
			pzip->inptr = (int)(pos - pzip->inbuf) + filenamlen;
			inflate(pzip);
		}
		beg = pos + filenamlen;
		siz = ptop - beg;
	}
}