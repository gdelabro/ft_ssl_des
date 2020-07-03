/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:37 by gdelabro          #+#    #+#             */
/*   Updated: 2020/07/03 12:33:05 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

static const	int g_s_md5[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static const	int g_k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

void			md5_init(t_ssl *ssl, t_md5 *md5, char *message)
{
	md5->a0 = 0x67452301;
	md5->b0 = 0xefcdab89;
	md5->c0 = 0x98badcfe;
	md5->d0 = 0x10325476;
	md5->nb_grps = 1 + (ssl->len + 8) / 64;
	if (!(md5->msg = malloc(64 * md5->nb_grps)))
		quit("malloc failed\n");
	ft_bzero(md5->msg, 64 * md5->nb_grps);
	ft_memcpy(md5->msg, message, ssl->len);
	md5->size = ssl->len * 8;
	md5->msg[ssl->len] = 0x80;
	ft_memcpy(md5->msg + (64 * md5->nb_grps) - 8, &(md5->size), 8);
	md5->grp = -1;
}

void			md5_compression(t_md5 *md5)
{
	while (++md5->i < 64)
	{
		if (md5->i / 16 == 0 && (md5->g = md5->i) != -1)
			md5->f = (md5->b & md5->c) | (~md5->b & md5->d);
		else if (md5->i / 16 == 1)
		{
			md5->f = (md5->d & md5->b) | (~md5->d & md5->c);
			md5->g = (5 * md5->i + 1) % 16;
		}
		else if (md5->i / 16 == 2)
		{
			md5->f = md5->b ^ md5->c ^ md5->d;
			md5->g = (3 * md5->i + 5) % 16;
		}
		else if (md5->i / 16 == 3)
		{
			md5->f = md5->c ^ (md5->b | ~md5->d);
			md5->g = (7 * md5->i) % 16;
		}
		md5->f = md5->f + md5->a + g_k[md5->i] + md5->m[md5->g];
		md5->a = md5->d;
		md5->d = md5->c;
		md5->c = md5->b;
		md5->b = md5->b + rotl(md5->f, g_s_md5[md5->i]);
	}
}

void			md5_funct(char *message, t_ssl *ssl)
{
	t_md5	md5;

	md5_init(ssl, &md5, message);
	while (++md5.grp < md5.nb_grps)
	{
		md5.m = (unsigned int*)(md5.msg + md5.grp * 64);
		md5.a = md5.a0;
		md5.b = md5.b0;
		md5.c = md5.c0;
		md5.d = md5.d0;
		md5.i = -1;
		md5_compression(&md5);
		md5.a0 += md5.a;
		md5.b0 += md5.b;
		md5.c0 += md5.c;
		md5.d0 += md5.d;
	}
	ssl->size_hash = 4;
	ssl->hash[0] = switch_endian(md5.a0);
	ssl->hash[1] = switch_endian(md5.b0);
	ssl->hash[2] = switch_endian(md5.c0);
	ssl->hash[3] = switch_endian(md5.d0);
	free(md5.msg);
}
