/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:48 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 21:27:02 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

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

uint64_t		reverse_uint64(uint64_t nb)
{
	uint64_t	ret;

	ret = (nb & 0x00000000000000ff) << 56;
	ret |= (nb & 0x000000000000ff00) << 40;
	ret |= (nb & 0x0000000000ff0000) << 24;
	ret |= (nb & 0x00000000ff000000) << 8;
	ret |= (nb & 0x000000ff00000000) >> 8;
	ret |= (nb & 0x0000ff0000000000) >> 24;
	ret |= (nb & 0x00ff000000000000) >> 40;
	ret |= (nb & 0xff00000000000000) >> 56;
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
