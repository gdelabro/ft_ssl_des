/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:40 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 21:25:39 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl.h"

void	determin_ssl_func(char *str, t_ssl *s, char **av)
{
	if (!ft_strcmp(str, "md5") || !ft_strcmp(str, "sha256")
		|| !ft_strcmp(str, "sha224"))
		s->ssl_command_type = 1;
	if (!ft_strcmp(str, "base64"))
		s->ssl_command_type = 2;
	if (!ft_strcmp(str, "des") || !ft_strcmp(str, "des-ecb")
		|| !ft_strcmp(str, "des-cbc"))
		s->ssl_command_type = 3;
	s->ssl_command_type == 1 ? hash_commands(str, s, av) : 0;
	s->ssl_command_type == 2 || s->ssl_command_type == 3 ?
		cipher_commands(str, s, av) : 0;
	if (!s->ssl_command_type)
		quit("invalid ssl command");
}

void	parsing(char **av, t_ssl *s)
{
	if (!av[1])
		quit("no ssl command selected");
	ft_bzero(s, sizeof(t_ssl));
	determin_ssl_func(av[1], s, av);
}
