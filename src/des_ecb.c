#include "../ft_ssl.h"

void		padding(t_des *d)
{
	uint8_t		*msg;

	if (d->len % 8 == 0)
		return ;
	if (!(msg = malloc((d->len / 8) * 8 + 8)))
		quit("malloc failed");
	ft_bzero(msg, (d->len / 8) * 8 + 8);
	ft_memcpy(msg, d->msg, d->len);
	free(d->msg);
	d->msg = msg;
}

void		des_ecb_encode(t_ssl *ssl, t_des *d)
{
	(void)ssl;
	padding(d);
	create_subKeys(d);
}
