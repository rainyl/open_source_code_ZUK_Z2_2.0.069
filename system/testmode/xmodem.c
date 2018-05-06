/* vi: set sw=4 ts=4: */
/*
 * Copyright:     Copyright (C) 2001, Hewlett-Packard Company
 * Author:        Christopher Hoover <ch@hpl.hp.com>
 * Description:   xmodem functionality for uploading of kernels
 *                and the like
 * Created at:    Thu Dec 20 01:58:08 PST 2001
 *
 * xmodem functionality for uploading of kernels and the like
 *
 * Copyright (C) 2001 Hewlett-Packard Laboratories
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 *
 * This was originally written for blob and then adapted for busybox.
 */

//usage:#define rx_trivial_usage
//usage:       "FILE"
//usage:#define rx_full_usage "\n\n"
//usage:       "Receive a file using the xmodem protocol"
//usage:
//usage:#define rx_example_usage
//usage:       "$ rx /tmp/foo\n"

//#include "libbb.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h> 
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/input.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <cutils/properties.h>
#include <errno.h>
#include <termios.h>

#include "testmode.h"

#define SOH 0x01
#define STX 0x02
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define BS  0x08
#define PAD 0x1A

/*
Cf:
  http://www.textfiles.com/apple/xmodem
  http://www.phys.washington.edu/~belonis/xmodem/docxmodem.txt
  http://www.phys.washington.edu/~belonis/xmodem/docymodem.txt
  http://www.phys.washington.edu/~belonis/xmodem/modmprot.col
*/

#define TIMEOUT 1
#define TIMEOUT_LONG 10
#define MAXERRORS 10

extern int g_uart_fd;
//#define read_fd  STDIN_FILENO
//#define write_fd STDOUT_FILENO
static int read_fd;
static int write_fd;

static ssize_t safe_write(int fd, const void *buf, size_t count)
{
	ssize_t n;

	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

/*
 * Write all of the supplied buffer out to a file.
 * This does multiple writes as necessary.
 * Returns the amount written, or -1 on an error.
 */
static ssize_t full_write(int fd, const void *buf, size_t len)
{
	ssize_t cc;
	ssize_t total;

	total = 0;

	while (len) {
		cc = safe_write(fd, buf, len);

		if (cc < 0) {
			if (total) {
				/* we already wrote some! */
				/* user can do another write to know the error code */
				return total;
			}
			return cc;  /* write() returns -1 on failure. */
		}

		total += cc;
		buf = ((const char *)buf) + cc;
		len -= cc;
	}

	return total;
}

static int read_byte(unsigned timeout)
{
	unsigned char buf;
	int n;

	alarm(timeout);
	/* NOT safe_read! We want ALRM to interrupt us */
	n = read(read_fd, &buf, 1);
	alarm(0);
	if (n == 1)
		return buf;
	return -1;
}

static int scom_receive(/*int read_fd, */int file_fd)
{
	unsigned char blockBuf[1024];
	int blockLength = 0;
	unsigned errors = 0;
	int wantBlockNo = 1;
	unsigned length = 0;
	int do_crc = 1;
	char reply_char;
	unsigned timeout = TIMEOUT_LONG;

	/* Flush pending input */
	tcflush(read_fd, TCIFLUSH);

	/* Ask for CRC; if we get errors, we will go with checksum */
	reply_char = 'C';
	full_write(write_fd, &reply_char, 1);

	for (;;) {
		int blockBegin;
		int blockNo, blockNoOnesCompl;
		int cksum_or_crc;
		int expected;
		int i, j;

		blockBegin = read_byte(timeout);
		if (blockBegin < 0)
			goto timeout;

		/* If last block, remove padding */
		if (blockBegin == EOT) {
			/* Data blocks can be padded with ^Z characters */
			/* This code tries to detect and remove them */
			if (blockLength >= 3
			 && blockBuf[blockLength - 1] == PAD
			 && blockBuf[blockLength - 2] == PAD
			 && blockBuf[blockLength - 3] == PAD
			) {
				while (blockLength
			           && blockBuf[blockLength - 1] == PAD
				) {
					blockLength--;
				}
			}
		}
		/* Write previously received block */
		if (blockLength) {
			errno = 0;
			if (full_write(file_fd, blockBuf, blockLength) != blockLength) {
				printf("can't write to file\n");
				goto fatal;
			}
		}

		timeout = TIMEOUT;
		reply_char = NAK;

		switch (blockBegin) {
		case SOH:
		case STX:
			break;
		case EOT:
			reply_char = ACK;
			full_write(write_fd, &reply_char, 1);
			return length;
		default:
			goto error;
		}

		/* Block no */
		blockNo = read_byte(TIMEOUT);
		if (blockNo < 0)
			goto timeout;

		/* Block no, in one's complement form */
		blockNoOnesCompl = read_byte(TIMEOUT);
		if (blockNoOnesCompl < 0)
			goto timeout;

		if (blockNo != (255 - blockNoOnesCompl)) {
			printf("bad block ones compl");
			goto error;
		}

		blockLength = (blockBegin == SOH) ? 128 : 1024;

		for (i = 0; i < blockLength; i++) {
			int cc = read_byte(TIMEOUT);
			if (cc < 0)
				goto timeout;
			blockBuf[i] = cc;
		}

		if (do_crc) {
			cksum_or_crc = read_byte(TIMEOUT);
			if (cksum_or_crc < 0)
				goto timeout;
			cksum_or_crc = (cksum_or_crc << 8) | read_byte(TIMEOUT);
			if (cksum_or_crc < 0)
				goto timeout;
		} else {
			cksum_or_crc = read_byte(TIMEOUT);
			if (cksum_or_crc < 0)
				goto timeout;
		}

		if (blockNo == ((wantBlockNo - 1) & 0xff)) {
			/* a repeat of the last block is ok, just ignore it. */
			/* this also ignores the initial block 0 which is */
			/* meta data. */
			goto next;
		}
		if (blockNo != (wantBlockNo & 0xff)) {
			printf("unexpected block no, 0x%08x, expecting 0x%08x", blockNo, wantBlockNo);
			goto error;
		}

		expected = 0;
		if (do_crc) {
			for (i = 0; i < blockLength; i++) {
				expected = expected ^ blockBuf[i] << 8;
				for (j = 0; j < 8; j++) {
					if (expected & 0x8000)
						expected = (expected << 1) ^ 0x1021;
					else
						expected = (expected << 1);
				}
			}
			expected &= 0xffff;
		} else {
			for (i = 0; i < blockLength; i++)
				expected += blockBuf[i];
			expected &= 0xff;
		}
		if (cksum_or_crc != expected) {
			//printf(do_crc ? "crc error, expected 0x%04x, got 0x%04x": "checksum error, expected 0x%02x, got 0x%02x", expected, cksum_or_crc);
			goto error;
		}

		wantBlockNo++;
		length += blockLength;
 next:
		errors = 0;
		reply_char = ACK;
		full_write(write_fd, &reply_char, 1);
		continue;
 error:
 timeout:
		errors++;
		if (errors == MAXERRORS) {
			/* Abort */

			/* If were asking for crc, try again w/o crc */
			if (reply_char == 'C') {
				reply_char = NAK;
				errors = 0;
				do_crc = 0;
				goto timeout;
			}
			printf("too many errors; giving up\n");
 fatal:
			/* 5 CAN followed by 5 BS. Don't try too hard... */
			safe_write(write_fd, "\030\030\030\030\030\010\010\010\010\010", 10);
			return -1;
		}

		/* Flush pending input */
		tcflush(read_fd, TCIFLUSH);

		full_write(write_fd, &reply_char, 1);
	} /* for (;;) */
}

#define USE_1K_XMODEM  1
#if (USE_1K_XMODEM)
	#define XMODEM_DATA_SIZE 	1024
	#define XMODEM_HEAD			STX
#else
	#define XMODEM_DATA_SIZE 	128
	#define XMODEM_HEAD 		SOH
#endif
static int scom_send(/*int read_fd, */int file_fd)
{
	unsigned char blockBuf[1029];
	int blockLength = 0;
	int blockNo = 0;
	unsigned errors = 0;
	unsigned retry_num = 0;
	unsigned length = 0;
	int reply_char;
	unsigned timeout = TIMEOUT_LONG;

	/* Flush pending input */
	tcflush(read_fd, TCIFLUSH);

	/* Waiting for signal NAK or 'C' from receiver */
	do{
		reply_char = read_byte(timeout);
		errors++;
		if(errors == MAXERRORS) {
            printf("%s: waiting for signal NAK error\n", __func__);
			return -1;
        }
	}while(reply_char < 0);

	if(reply_char != 'C') {
        printf("%s: reply_char != C, reply_char = %d\n", __func__, reply_char);
		return -1;
    }

	printf("%s: Start transport...\n", __func__);
	for (;;) {
		int i, j;
		int nread = 0;
		int expected = 0;
		unsigned char *packetData = &blockBuf[3];

		if(reply_char != 'C')
			reply_char = read_byte(timeout);
		if (reply_char < 0) {
            printf("%s : %d\n", __func__, __LINE__);
			goto error;
        }

		switch (reply_char) {
		case 'C':
		case ACK:
			break;
		case NAK:
			if(retry_num++ > 10){
				printf("%s : Retry too many times\n", __func__);
				return -1;
			}
			full_write(write_fd, blockBuf, XMODEM_DATA_SIZE+5);
			break;
		default:
			goto error;
		}

		blockNo++;
		nread = read(file_fd, packetData, XMODEM_DATA_SIZE);
		if(nread>0){
			if(nread < XMODEM_DATA_SIZE)	// file with 0x1A
				memset(&packetData[nread], PAD, (XMODEM_DATA_SIZE-nread));

			blockBuf[0] = XMODEM_HEAD; 	// SOH
			blockBuf[1] = (char)(blockNo);	// packet num
			blockBuf[2] = (char)(255 - blockBuf[1]);

			// calculate crc value
			for (i = 0; i < XMODEM_DATA_SIZE; i++) {
				expected = expected ^ packetData[i] << 8;
				for (j = 0; j < 8; j++) {
					if (expected & 0x8000)
						expected = (expected << 1) ^ 0x1021;
					else
						expected = (expected << 1);
				}
			}
			expected &= 0xffff;

			blockBuf[XMODEM_DATA_SIZE+3] = (unsigned char)(expected >> 8);
			blockBuf[XMODEM_DATA_SIZE+4] = (unsigned char)(expected);

			printf("Transport %d byte\n", nread);
			full_write(write_fd, blockBuf, XMODEM_DATA_SIZE+5);
			length += nread;
		}else {
			// end of transport
			do{
				reply_char = EOT;
				full_write(write_fd, &reply_char, 1);
				reply_char = read_byte(timeout);
			}while(reply_char != ACK);
			printf("Transport complete\n");
			return length;
		}
next:
		errors = 0;
		continue;
		
 error:
		errors++;
		if (errors == MAXERRORS) {
			printf("too many errors; giving up\n");
			return -1;
		}

		/* Flush pending input */
		tcflush(read_fd, TCIFLUSH);
	} /* for (;;) */

	return -1;
}

static void sigalrm_handler(int signum)
{
}

static void signal_no_SA_RESTART_empty_mask(int sig, void (*handler)(int))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	/*sigemptyset(&sa.sa_mask);*/
	/*sa.sa_flags = 0;*/
	sa.sa_handler = handler;
	sigaction(sig, &sa, NULL);
}

// dir: 0 - receive, 1 - send
int scom_main(char *filename, int dir)
{
	struct termios tty, orig_tty;
	int termios_err;
	int file_fd;
	int flags, ret;

	/* Disabled by vda:
	 * why we can't receive from stdin? Why we *require*
	 * controlling tty?? */
	/*read_fd = xopen(CURRENT_TTY, O_RDWR);*/
	if(dir)
		file_fd = open(filename, O_RDONLY);
	else
		file_fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if(file_fd<0) {
        printf("%s:%s open failed\n", __func__,filename);
		return -1;
    }

	read_fd = write_fd = g_uart_fd;
	termios_err = tcgetattr(read_fd, &tty);
	if (termios_err == 0) {
		orig_tty = tty;
		cfmakeraw(&tty);
		tcsetattr(read_fd, TCSAFLUSH, &tty);
	}
	flags = fcntl(read_fd, F_GETFL);
	fcntl(read_fd, F_SETFL, flags&(~O_NONBLOCK));

	/* No SA_RESTART: we want ALRM to interrupt read() */
	signal_no_SA_RESTART_empty_mask(SIGALRM, sigalrm_handler);

	if(dir) {
        printf("%s : scom_send\n", __func__);
		ret = scom_send(file_fd);
    }
	else {
        printf("%s : scom_receive\n", __func__);
		ret = scom_receive(file_fd);
    }

	if (termios_err == 0)
		tcsetattr(read_fd, TCSAFLUSH, &orig_tty);
	fcntl(read_fd, F_SETFL, flags);
	close(file_fd);
	//fflush_stdout_and_exit(n >= 0);
	return ret;
}

