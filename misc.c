#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include "common.h"

int ch2hex(char c)
{
	if (c >= '0' && c <= '9') c = c - '0';
	else if (c >= 'a' && c <='f') c = c - 'a' + 10;
	else if (c >= 'A' && c <='F') c = c - 'A' + 10;

	return c;
}

int str2hex(char *str, uint8_t *hex)
{
	int     len, i;
	uint8_t *p;

	len = strlen(str)/2;
	for(i=0,p=str;i<len;i++)
	{
		hex[i] = ch2hex(*p) << 4 | ch2hex(*(p+1));
		p += 2;
	}

	return 0;
}

int aes128_dec(unsigned char *key, unsigned char *in, unsigned char *out, size_t len)
{
	int				ret = RESULT_OK;
	int				fd;
	crypto_arg_t	c_arg = 
	{
		.key_len	= 16,
		.in_len		= len,
		.out_len	= len,
		.key		= key,
		.in			= in,
		.out		= out,
	};

	fd = open(CRYPTO_DEV, O_RDWR | O_NDELAY);
	if(fd <= 0)
	{
		return RESULT_FAIL;
	}

	ret = ioctl(fd, CRYPTO_DEC, & c_arg);
	close(fd);

	if(ret)
	{
		PRINT(ERROR, "DEC ioctl error[%s]\n", strerror(errno));
		return RESULT_FAIL;
	}

	return (ret < len) ? RESULT_FAIL : ret;
}

int get_intf_status(char *intf_name)
{
	int		fd;
	char	cmd[128] = {0, };
	char	buff[2] = {0, };

	sprintf(cmd, "/sys/class/net/%s/carrier", intf_name);

	fd = open(cmd, O_RDWR | O_NDELAY);
	if(fd <= 0)
	{
		return RESULT_FAIL;
	}

	if(read(fd, buff, 1))
		return atoi(buff);
	else
		return RESULT_FAIL;
}

int make_socket_non_blocking (int sfd)
{
	int flags, s;

	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1)
	{
		PRINT(ERROR, "get fcntl failed - err : %d\n", errno);
		return RESULT_FAIL;
	}

	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
	if (s == -1)
	{
		PRINT(ERROR, "set fcntl failed - err : %d\n", errno);
		return RESULT_FAIL;
	}

	return RESULT_OK;
}
