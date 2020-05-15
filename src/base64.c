#include "../ssl_des.h"

static char *base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk\
lmnopqrstuvwxyz0123456789+/";

void	aff_code(char *str, int fd)
{
	int		i;
	int		i2;

	i2 = 0;
	i = ft_strlen(str);
	while (i > 0)
	{
		write(fd, str + i2 * 64, i > 64 ? 64 : i);
		write(fd, "\n", 1);
		i -= 64;
		i2++;
	}
}

void	base64_decode(t_ssl *s, t_b64 *b)
{
	(void)s;
	(void)b;
	(void)base64chars;
}

void	init_result(t_ssl *s, t_b64 *b)
{
	if (!s->len)
		return ;
	b->size_result = ((s->len / 3) + ((s->len % 3) ? 1 : 0)) * 4;
	if (!(b->result = malloc(b->size_result + 1)))
		quit("malloc failed");
	b->result[b->size_result] = 0;
	ft_memset(b->result, '=', b->size_result);
	b->i = 0;
	b->index = 0;
}

void	base64_encode(t_ssl *s, t_b64 *b)
{
	init_result(s, b);
	while (b->i < s->len)
	{
		b->nb = ((int)b->msg[b->i]) << 16;
		b->i + 1 < s->len ? b->nb += ((int)b->msg[b->i + 1]) << 8 : 0;
		b->i + 2 < s->len ? b->nb += ((int)b->msg[b->i + 2]) : 0;
		b->n[0] = (unsigned char)(b->nb >> 18) & 63;
		b->n[1] = (unsigned char)(b->nb >> 12) & 63;
		b->n[2] = (unsigned char)(b->nb >> 6) & 63;
		b->n[3] = (unsigned char)(b->nb) & 63;
		b->result[b->index++] = base64chars[b->n[0]];
		b->result[b->index++] = base64chars[b->n[1]];
		b->i + 1 < s->len ? b->result[b->index++] = base64chars[b->n[2]] : 0;
		b->i + 2 < s->len ? b->result[b->index++] = base64chars[b->n[3]] : 0;
		b->i += 3;
	}
	aff_code(b->result, b->fd2);
}

void	base64(t_ssl *s)
{
	t_b64			b;
	int				i;

	ft_memset(&b, 0, sizeof(b));
	!s->d && !s->e ? ++s->e : 0;
	s->d && s->e ? --s->d : 0;
	b.fd2 = 1;
	if (s->i)
		if ((b.fd = open(s->i, O_RDONLY)) < 0 || fstat(b.fd, &(b.st)) != 0
		|| !S_ISREG(b.st.st_mode))
			quit("can't open/read file input");
	if (s->o)
		if ((b.fd2 = open(s->o, O_WRONLY | O_CREAT
		| O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
			quit("can't open/write file output");
	while ((i = read(b.fd, b.buf, 500)) > 0)
	{
		b.buf[i] = 0;
		b.tmp = malloc(s->len + i + 1);
		s->len ? ft_memcpy(b.tmp, b.msg, s->len) : 0;
		ft_memcpy(b.tmp + s->len, b.buf, i + 1);
		s->len ? free(b.msg) : 0;
		b.msg = b.tmp;
		s->len += i;
	}
	s->e ? base64_encode(s, &b) : base64_decode(s, &b);
}
