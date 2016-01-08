/*
 * lstdio.c
 *
 *       Light stdio library
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "lstdio.h"


lFILE *lfopen (char *filename, int buf_size)
{
	lFILE *mfp;

	/* malloc the lFILE structure */
	mfp = (lFILE *) malloc (sizeof (lFILE));
	if (mfp == NULL) {
		fprintf (stderr, "cannot malloc lFILE structure: %s\n", 
				strerror(errno));
		return NULL;
	}

	mfp->w_offset = 0;
	mfp->r_offset = 0;
	mfp->r_nbytes = 0;
	mfp->buf_size = buf_size;

	/* malloc the read and write buffers */
	mfp->r_buf = (char *) malloc (mfp->buf_size);
	if (mfp->r_buf == NULL) {
		fprintf (stderr, "cannot malloc %i bytes: %s\n", mfp->buf_size, 
				strerror(errno));
		return NULL;
	}
	mfp->w_buf = (char *) malloc (mfp->buf_size);
	if (mfp->w_buf == NULL) {
		fprintf (stderr, "cannot malloc %i bytes: %s\n", mfp->buf_size, 
				strerror(errno));
		return NULL;
	}

	if ((mfp->fd = open (filename, O_WRONLY|O_CREAT|O_TRUNC, 
				S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
		fprintf (stderr, "cannot open %s: %s\n", filename, strerror(errno));
		return NULL;
	}

	return mfp;
}



lFILE *lfdopen (int fd, int buf_size)
{
	lFILE *mfp;

	/* malloc the lFILE structure */
	mfp = (lFILE *) malloc (sizeof (lFILE));
	if (mfp == NULL) {
		fprintf (stderr, "cannot malloc lFILE structure: %s\n", 
				strerror(errno));
		return NULL;
	}

	mfp->w_offset = 0;
	mfp->r_offset = 0;
	mfp->r_nbytes = 0;
	mfp->buf_size = buf_size;

	/* malloc the buffer */
	mfp->r_buf = (char *) malloc (mfp->buf_size);
	if (mfp->r_buf == NULL) {
		fprintf (stderr, "cannot malloc %i bytes: %s\n", mfp->buf_size, 
				strerror(errno));
		return NULL;
	}
	mfp->w_buf = (char *) malloc (mfp->buf_size);
	if (mfp->w_buf == NULL) {
		fprintf (stderr, "cannot malloc %i bytes: %s\n", mfp->buf_size, 
				strerror(errno));
		return NULL;
	}

	mfp->fd = fd;

	return mfp;
}



int lfileno (lFILE *mfp)
{
	return mfp->fd;
}



/* PERFORMANCE
long total_written = 0;
*/

int lfclose (lFILE *mfp) 
{
	if (mfp == NULL) {
		return -1;
	}
	lfflush (mfp);
/* PERFORMANCE
printf ("TOTAL BYTES WRITTEN: %li\n", total_written);
*/
	if (mfp->r_buf != NULL) {
		free (mfp->r_buf);
	}
	if (mfp->w_buf != NULL) {
		free (mfp->w_buf);
	}
	close (mfp->fd);
	free (mfp);
	return 0;
}


int lfread (lFILE *mfp, char *buf, int size)
{
	int _size;
	int _offset;

	_size = size;
	_offset = 0;

	while (_size > (mfp->r_nbytes - mfp->r_offset)) {
		memcpy ((char *)(buf + _offset), mfp->r_buf + mfp->r_offset, 
				mfp->r_nbytes - mfp->r_offset);
		_offset += mfp->r_nbytes - mfp->r_offset;
		_size -= mfp->r_nbytes - mfp->r_offset;
		mfp->r_offset = 0;

again:
		mfp->r_nbytes = read (mfp->fd, mfp->r_buf, mfp->buf_size);
		if (mfp->r_nbytes < 0) {
			if (errno == EINTR) {
				goto again;
			}

			/* close the fd */
			if (mfp->fd >= 0) {
				close (mfp->fd);
				mfp->fd = -1;
			}

			perror ("read()");
			exit(1);

		} else if (mfp->r_nbytes == 0) {
			/* eof in the fd */

			/* close the fd */
			if (mfp->fd >= 0) {
				close (mfp->fd);
				mfp->fd = -1;
			}

			return 0;
		}
	}

	memcpy ((char *)(buf + _offset), mfp->r_buf + mfp->r_offset, _size);
	mfp->r_offset += _size;

	return size;
}



int lfwrite (lFILE *mfp, void *buf, int size)
{
	int _size;
	int _offset;

	_size = size;
	_offset = 0;

	while ((mfp->w_offset + _size) >= mfp->buf_size) {
		memcpy (mfp->w_buf + mfp->w_offset, (char *)buf + _offset, 
				mfp->buf_size - mfp->w_offset);
/* PERFORMANCE
total_written += mfp->buf_size;
*/
		write (mfp->fd, mfp->w_buf, mfp->buf_size);
		_offset += mfp->buf_size - mfp->w_offset;
		_size -= mfp->buf_size - mfp->w_offset;
		mfp->w_offset = 0;
	}

	memcpy (mfp->w_buf + mfp->w_offset, (char *)buf + _offset, _size);
	mfp->w_offset += _size;

	return size;
}



int lfflush (lFILE *mfp)
{
	write (mfp->fd, mfp->w_buf, mfp->w_offset);
/* PERFORMANCE
total_written += mfp->w_offset;
*/
	mfp->w_offset = 0;
	return 0;
}


