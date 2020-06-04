#include "../ft_ssl.h"

uint64_t	ft_pbkdf(t_ssl *s, char *passwd, uint64_t salt)
{
	uint64_t	xored;
	int			tmp;

	tmp = s->len;
	s->len = ft_strlen(passwd);
	md5_funct(passwd, s);
	xored = *(uint64_t*)s->hash;
	s->len = 8;
	md5_funct((char*)&salt, s);
	salt = *(uint64_t*)s->hash;
	salt ^= xored;
	s->len = tmp;
	return (salt);
}

uint64_t	transform_hex_to_uint64(char *str)
{
	uint64_t	nb;
	int			i;

	nb = 0;
	i = -1;
	while (++i < 16)
	{
		nb <<= 4;
		if (i >= (int)ft_strlen(str))
			continue ;
		if (str[i] >= '0' && str[i] <= '9')
			nb += str[i] - '0';
		else if (str[i] >= 'A' && str[i] <= 'F')
			nb += str[i] - 'A' + 10;
		else if (str[i] >= 'a' && str[i] <= 'f')
			nb += str[i] - 'a' + 10;
		else
			quit("bad character in hex number");
	}
	return (nb);
}

void		key_gen(t_ssl *s, t_des *d)
{
	if (s->pass)
		d->pass = s->pass;
	else if (!s->k)
		d->pass = getpass("enter des encryption password:");
	d->salt = 0;
	if (s->s)
		d->salt = transform_hex_to_uint64(s->s);
	else if (!s->k)
		getentropy(&d->salt, 8);
	if (s->k)
		d->key = transform_hex_to_uint64(s->k);
	else
		d->key = ft_pbkdf(s, d->pass, d->salt);
	!s->k ? fd_printf(2, "key created: %.16lX\n", d->key) : 0;
}

void	des_luncher(t_ssl *s, t_des *d)
{
	int				i;

	d->fd2 = 1;
	if (s->i)
		if ((d->fd = open(s->i, O_RDONLY)) < 0 || fstat(d->fd, &(d->st)) != 0
		|| !S_ISREG(d->st.st_mode))
			quit("can't open/read file input");
	if (s->o && (d->fd2 = open(s->o, O_WRONLY | O_CREAT | O_TRUNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0)
			quit("can't open/write file output");
	while ((i = read(d->fd, d->buf, 500)) > 0)
	{
		d->buf[i] = 0;
		if (!(d->tmp = malloc(d->len + i + 1)))
			quit("malloc failed\n");
		d->len ? ft_memcpy(d->tmp, d->msg, d->len) : 0;
		ft_memcpy(d->tmp + d->len, d->buf, i + 1);
		d->len ? free(d->msg) : 0;
		d->msg = (uint8_t*)d->tmp;
		d->len += i;
	}
	des_func(s, d);
}

void		des_init(char *str, t_ssl *s)
{
	t_des d;

	ft_bzero(&d, sizeof(t_des));
	!ft_strcmp(str, "des-cbc") ? d.cbc = 1 : 0;
	s->e ? s->d = 0 : 0;
	!s->d ? s->e = 1 : 0;
	if (!s->k && s->d)
		quit("no key for decode mode");
	if (d.cbc && !s->v)
		quit("no initialization vector for cbc mode");
	d.cbc ? d.iv = transform_hex_to_uint64(s->v) : 0;
	s->e ? key_gen(s, &d) : 0;
	s->d ? d.key = transform_hex_to_uint64(s->k) : 0;
	des_luncher(s, &d);
}
