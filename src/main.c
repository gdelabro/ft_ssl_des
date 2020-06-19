/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:33 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 21:22:45 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

void	quit(char *str)
{
	fd_printf(2, "ft_ssl: %s\n\nStandard commands:\n\nMessage Digest Commands:\
\nmd5\nsha256\nsha224\n\nCipher Commands:\nbase64\ndes\ndes-ecb\n\
des-cbc\n", str);
	exit(0);
}

int		main(int ac, char **av)
{
	t_ssl	s;
	int		n;

	(void)ac;
	n = 1;
	s.little_endian = *(char*)&n;
	parsing(av, &s);
	return (0);
}
