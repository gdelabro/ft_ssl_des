/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   create_subkeys.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:10 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 21:19:53 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

uint64_t	takebitnumber(uint64_t key, int bit, int keysize)
{
	return ((key >> (keysize - bit)) & 1);
}

uint32_t	left_shift_28(uint32_t key, int shifts)
{
	uint32_t		lbits;

	lbits = (key & 0xC000000);
	key <<= 4 + shifts;
	key >>= 4;
	key |= lbits >> (28 - shifts);
	return (key);
}

uint64_t	permutate(uint64_t key, const uint8_t *tab, int oldkeyl, int keyl)
{
	int			i;
	uint64_t	k;

	k = 0;
	i = -1;
	while (++i < keyl)
	{
		k <<= 1;
		k |= takebitnumber(key, tab[i], oldkeyl);
	}
	return (k);
}

void		create_subkeys(t_des *d)
{
	int		i;

	d->k[0] = permutate(d->key, g_pc1, 64, 56);
	d->c[0] = d->k[0] >> 28;
	d->d[0] = d->k[0] & 0xFFFFFFF;
	i = 0;
	while (++i < 17)
	{
		d->c[i] = left_shift_28(d->c[i - 1], g_shifts[i - 1]);
		d->d[i] = left_shift_28(d->d[i - 1], g_shifts[i - 1]);
		d->k[i] = ((uint64_t)(d->c[i]) << 28) + d->d[i];
	}
	i = 0;
	while (++i < 17)
		d->k[i] = permutate(d->k[i], g_pc2, 56, 48);
}
