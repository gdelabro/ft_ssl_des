/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha_funct.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 21:30:56 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 21:44:38 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

uint32_t	maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
}

uint32_t	e0(uint32_t x)
{
	return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22));
}

uint32_t	e1(uint32_t x)
{
	return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25));
}

uint32_t	o0(uint32_t x)
{
	return (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3));
}

uint32_t	o1(uint32_t x)
{
	return (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10));
}
