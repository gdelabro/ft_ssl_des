/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_alg.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:14 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/22 15:35:38 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

void		padding(t_des *d)
{
	uint8_t		*msg;
	uint8_t		padd;

	d->size_result = (d->len / 8) * 8 + 8;
	padd = d->size_result - d->len;
	if (!(d->result = malloc(d->size_result)))
		quit("malloc failed");
	if (!(msg = malloc(d->size_result)))
		quit("malloc failed");
	ft_memset(msg, padd, d->size_result);
	ft_memcpy(msg, d->msg, d->len);
	free(d->msg);
	d->msg = msg;
}

void		malloc_result(t_des *d)
{
	if (d->len % 8 || d->len < 8)
		quit("bad size of the message");
	d->size_result = d->len;
	if (!(d->result = malloc(d->size_result)))
		quit("malloc failed");
}

uint32_t	f(uint32_t r, uint64_t key)
{
	uint64_t	e;
	uint32_t	ret;
	int			i;

	e = permutate(r, g_e, 32, 48);
	e ^= key;
	ret = 0;
	i = -1;
	while (++i < 8)
	{
		ret >>= 4;
		ret |= g_s[7 - i][((e & 0b11110) >> 1) +
			((e & 1) + (((e >> 5) & 1) << 1)) * 16] << 28;
		e >>= 6;
	}
	ret = permutate(ret, g_p, 32, 32);
	return (ret);
}

void		block_encryption(t_des *d, uint8_t enc)
{
	uint32_t	i;
	uint64_t	block;

	i = 0;
	while (i < d->size_result)
	{
		d->m = reverse_uint64(*(uint64_t*)(d->msg + i));
		d->cbc && enc ? d->m ^= d->iv : 0;
		d->ip = permutate(d->m, g_ip, 64, 64);
		d->l[0] = d->ip >> 32;
		d->r[0] = d->ip;
		d->i = 0;
		while (++d->i < 17)
		{
			d->l[d->i] = d->r[d->i - 1];
			d->r[d->i] = d->l[d->i - 1] ^ f(d->r[d->i - 1], d->k[d->i]);
		}
		block = ((uint64_t)d->r[16] << 32) + d->l[16];
		block = permutate(block, g_ip2, 64, 64);
		enc ? d->iv = block : 0;
		d->cbc && !enc ? block ^= d->iv : 0;
		!enc ? d->iv = d->m : 0;
		*(uint64_t*)(d->result + i) = reverse_uint64(block);
		i += 8;
	}
}

void		des_func(t_ssl *ssl, t_des *d)
{
	int i;

	i = 0;
	ssl->a && ssl->d ? base64_des(ssl, d) : 0;
	ssl->e ? padding(d) : malloc_result(d);
	create_subkeys(d);
	while (++i < 9 && ssl->d)
	{
		d->k[i] ^= d->k[17 - i];
		d->k[17 - i] ^= d->k[i];
		d->k[i] ^= d->k[17 - i];
	}
	block_encryption(d, ssl->e);
	ssl->a && ssl->e ? base64_des(ssl, d) : 0;
	ssl->d && (uint8_t)d->result[d->size_result - 1] > 8 ?
		quit("bad padding at the end") : 0;
	ssl->d ? d->size_result -= (uint8_t)d->result[d->size_result - 1] : 0;
	!ssl->a || ssl->d ? write(d->fd2, d->result, d->size_result) :
		aff_code((char*)d->result, d->fd2);
	free(d->msg);
	free(d->result);
	d->fd2 > 2 ? close(d->fd2) : 0;
}
