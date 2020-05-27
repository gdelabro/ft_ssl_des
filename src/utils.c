#include "../ft_ssl.h"

unsigned int	switch_endian(unsigned int nb)
{
	int ret;

	ret = 0;
	ret |= (nb & 0xff000000) >> 24;
	ret |= (nb & 0x00ff0000) >> 8;
	ret |= (nb & 0x0000ff00) << 8;
	ret |= (nb & 0x000000ff) << 24;
	return (ret);
}

unsigned int	rotl(unsigned int nb, unsigned int rot)
{
	return ((nb << rot) | (nb >> (32 - rot)));
}

unsigned int	rotr(unsigned int nb, unsigned int rot)
{
	return ((nb >> rot) | (nb << (32 - rot)));
}
