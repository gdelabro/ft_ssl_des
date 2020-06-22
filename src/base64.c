/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:03:43 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/22 15:41:48 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

static const char *g_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
"lmnopqrstuvwxyz0123456789+/";

void			aff_code(char *str, int fd)
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

void			init_result(t_ssl *s, t_b64 *b)
{
	if (!s->len)
		return ;
	b->size_result = ((s->len / 3) + ((s->len % 3) ? 1 : 0)) * 4;
	if (!(b->result = malloc(b->size_result + 1)))
		quit("malloc failed");
	b->result[b->size_result] = 0;
	b->i = 0;
	b->index = 0;
}

void			base64_encode(t_ssl *s, t_b64 *b)
{
	init_result(s, b);
	while (b->i < s->len)
	{
		b->nb = ((uint32_t)b->msg[b->i]) << 16;
		b->i + 1 < s->len ? b->nb |= ((uint32_t)b->msg[b->i + 1]) << 8 : 0;
		b->i + 2 < s->len ? b->nb |= ((uint32_t)b->msg[b->i + 2]) : 0;
		b->n[0] = (uint8_t)(b->nb >> 18) & 63;
		b->n[1] = (uint8_t)(b->nb >> 12) & 63;
		b->n[2] = (uint8_t)(b->nb >> 6) & 63;
		b->n[3] = (uint8_t)(b->nb) & 63;
		b->result[b->index++] = g_base64chars[b->n[0]];
		b->result[b->index++] = g_base64chars[b->n[1]];
		b->result[b->index++] = b->i + 1 < s->len ?
			g_base64chars[b->n[2]] : '=';
		b->result[b->index++] = b->i + 2 < s->len ?
			g_base64chars[b->n[3]] : '=';
		b->i += 3;
	}
	s->ssl_command_type == 2 ? aff_code((char*)b->result, b->fd2) : 0;
	s->ssl_command_type == 2 ? free(b->result) : 0;
}

void			base64_des(t_ssl *s, t_des *d)
{
	t_b64			b;

	ft_memset(&b, 0, sizeof(b));
	b.msg = s->e ? d->result : d->msg;
	s->len = s->e ? d->size_result : d->len;
	s->e ? base64_encode(s, &b) : base64_decode(s, &b);
	if (s->e)
	{
		free(d->result);
		d->result = b.result;
		d->size_result = b.size_result;
	}
	else
	{
		free(d->msg);
		d->msg = b.result;
		d->len = b.size_result;
	}
}

void			base64(t_ssl *s)
{
	t_b64			b;

	ft_memset(&b, 0, sizeof(b));
	!s->d && !s->e ? ++s->e : 0;
	s->d && s->e ? --s->d : 0;
	b.fd2 = 1;
	if (s->i && ((b.fd = open(s->i, O_RDONLY)) < 0 || fstat(b.fd, &(b.st)) != 0
		|| !S_ISREG(b.st.st_mode)))
		quit("can't open/read file input");
	if (s->o && (b.fd2 = open(s->o, O_WRONLY | O_CREAT | O_TRUNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0)
		quit("can't open/write file output");
	while ((b.i = read(b.fd, b.buf, 500)) > 0)
	{
		b.buf[b.i] = 0;
		!(b.tmp = malloc(s->len + b.i + 1)) ? quit("malloc failed") : 0;
		s->len ? ft_memcpy(b.tmp, b.msg, s->len) : 0;
		ft_memcpy(b.tmp + s->len, b.buf, b.i + 1);
		s->len ? free(b.msg) : 0;
		b.msg = (uint8_t*)b.tmp;
		s->len += b.i;
	}
	b.fd > 2 ? close(b.fd) : 0;
	s->e ? base64_encode(s, &b) : base64_decode(s, &b);
	b.fd2 > 2 ? close(b.fd2) : 0;
}
