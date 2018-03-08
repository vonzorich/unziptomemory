# unziptomemory
unzip compressed buffer to memory. Derived from gzip source code.

## Compilation:
        gcc -D_GNU_SOURCE main.c inflate.c

## usage:


### list files in the zip archive:

                bzero(&zip);
                zip.inbuf = CompressedDataBufer;
                zip.inbufsiz = CompressedDataBufferSize;
                unzip(&zip, NULL);

### get decompressed data size for given file "foo/bar"

                bzero(&zip);
                zip.inbuf = CompressedDataBufer;
                zip.inbufsiz = CompressedDataBufferSize;
                unzip(&zip, "foo/bar");

### decompresse given file "foo/bar"

                bzero(&zip);
                zip.inbuf = CompressedDataBufer;
                zip.inbufsiz = CompressedDataBufferSize;
                zip.outbuf = malloc(DecompressedDataSize);
                unzip(&zip, "foo/bar");
