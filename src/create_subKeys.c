#include "../ft_ssl.h"

uint64_t	takeBitNumber(uint64_t key, int bit, int keysize)
{
	int		i;

	i = 0;
	keysize++;
	while (++i < keysize - bit)
		key >>= 1;
	return (key & 1);
}

uint32_t	left_shift_28(uint32_t key, int shifts)
{
	uint32_t		lBits;

	lBits = (key & 0xC000000);
	key <<= 4 + shifts;
	key >>= 4;
	key |= lBits >> (28 - shifts);
	return (key);
}

uint64_t	new_key(uint64_t key)
{
	uint64_t	k;
	int			i;

	k = 0;
	i = -1;
	while (++i < 48)
	{
		k <<= 1;
		k |= takeBitNumber(key, g_PC2[i], 56);
	}
	return (k);
}

void		create_subKeys(t_des *d)
{
	int		i;

	i = -1;
	while (++i < 56)
	{
		d->k[0] <<= 1;
		d->k[0] |= takeBitNumber(d->key, g_PC1[i], 64);
	}
	d->c[0] = d->k[0] >> 28;
	d->d[0] = d->k[0] & 0xFFFFFFF;
	i = 0;
	while (++i < 17)
	{
		d->c[i] = left_shift_28(d->c[i - 1], g_SHIFTS[i - 1]);
		d->d[i] = left_shift_28(d->d[i - 1], g_SHIFTS[i - 1]);
		d->k[i] = ((uint64_t)(d->c[i]) << 28) + d->d[i];
	}
	i = 0;
	while (++i < 17)
	{
		d->k[i] = new_key(d->k[i]);
		ft_printf("K[%d] = %.48lb\n", i, d->k[i]);
	}
}
