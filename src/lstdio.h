/*
 * lstdio.h
 *
 *       Light stdio library header
 *
 * Copyright (c) 2002 - 2002 Jose Maria Gonzalez (chema@cs.berkeley.edu)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * A. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * B. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * C. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _LSTDIO_H
#define _LSTDIO_H 1


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>

/*
 * Discussion
 *
 * lstdio implements user read and write buffering. In both cases, the 
 * goal is to enhance the performance of small writes and/or reads. 
 *
 * At any moment, an lFILE structure has two buffers, the read one and 
 * the write one. Both have the same size (buf_size variable). The 
 * buffer size is selected by the user when opening the file.
 *
 * The write buffer (w_buf pointer) is controlled by one variable, 
 * w_offset. w_offset states how many bytes are valid in the write 
 * buffer (starting from w_buf). If an lfwrite call does not fill the 
 * write buffer, the contents are appended to it and w_offset is 
 * advanced accordingly. 
 *
 * The read buffer (r_buf pointer) is controlled by two variables, 
 * r_offset and r_nbytes. r_offset states how many bytes are valid but 
 * have been read already. r_nbytes states how many bytes are valid. 
 * The read buffer has at any moment (r_nbytes - r_offset) valid, 
 * unread bytes (starting from r_buf - r_offset).
 */

struct l_IO_FILE {
	int fd;
	char* w_buf;
	char* r_buf;
	int w_offset;
	int r_offset;
	int r_nbytes;
	int buf_size;
};
typedef struct l_IO_FILE lFILE;


lFILE *lfopen (char *filename, int buf_size);
lFILE *lfdopen (int fd, int buf_size);
int lfileno (lFILE *mfp);
int lfclose (lFILE *mfp);
int lfread (lFILE *mfp, char *buf, int size);
int lfwrite (lFILE *mfp, void *buf, int size);
int lfflush (lFILE *mfp);

#endif /* lstdio.h */

