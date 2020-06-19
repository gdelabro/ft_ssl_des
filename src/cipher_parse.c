/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   cipher_parse.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:05 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 20:04:05 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

void	des_arg(t_ssl *s, char **av)
{
	s->len = 1;
	while (av[++s->len])
	{
		if (!ft_strcmp(av[s->len], "-a"))
			s->a = 1;
		else if (!ft_strcmp(av[s->len], "-d"))
			s->d = 1;
		else if (!ft_strcmp(av[s->len], "-e"))
			s->e = 1;
		else if (!ft_strcmp(av[s->len], "-i"))
			s->i = av[++s->len];
		else if (!ft_strcmp(av[s->len], "-o"))
			s->o = av[++s->len];
		else if (!ft_strcmp(av[s->len], "-k"))
			s->k = av[++s->len];
		else if (!ft_strcmp(av[s->len], "-p"))
			s->pass = av[++s->len];
		else if (!ft_strcmp(av[s->len], "-s"))
			s->s = av[++s->len];
		else if (!ft_strcmp(av[s->len], "-v"))
			s->v = av[++s->len];
		else
			quit("bad argument");
	}
	s->len = 0;
}

void	base64_arg(t_ssl *s, char **av)
{
	int i;

	i = 1;
	while (av[++i])
	{
		if (!ft_strcmp(av[i], "-d"))
			s->d = 1;
		else if (!ft_strcmp(av[i], "-e"))
			s->e = 1;
		else if (!ft_strcmp(av[i], "-i") && ++i)
			!s->i ? s->i = av[i] : 0;
		else if (!ft_strcmp(av[i], "-o") && ++i)
			!s->o ? s->o = av[i] : 0;
		else
			quit("bad argument");
	}
	if (s->i && s->o && !ft_strcmp(s->i, s->o))
		quit("same file for input and output");
}

void	cipher_commands(char *str, t_ssl *s, char **av)
{
	if (!ft_strcmp(str, "base64"))
	{
		ft_memcpy(s->hash_name, "BASE64", 7);
		base64_arg(s, av);
		base64(s);
	}
	else
	{
		des_arg(s, av);
		if (s->i && s->o && !ft_strcmp(s->i, s->o))
			quit("same file for input and output");
		des_init(str, s);
	}
}
