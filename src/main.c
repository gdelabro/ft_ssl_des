/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:04:33 by gdelabro          #+#    #+#             */
/*   Updated: 2020/07/03 14:04:34 by gdelabro         ###   ########.fr       */
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

void	transform_line(char *line)
{
	int i;
	int esc;

	i = -1;
	esc = 0;
	while (line[++i])
	{
		if (is_space(line[i]) && !esc)
			line[i] = -1;
		else if (!esc && (line[i] == '\"' || line[i] == '\''))
		{
			esc = line[i];
			line[i] = -1;
		}
		else if (line[i] == esc)
		{
			esc = 0;
			line[i] = -1;
		}
	}
}

char	**pars_stdin_argument(void)
{
	char	buf[10000];
	char	**arg;
	char	**new_arg;
	int		i;
	int		i2;

	ft_printf("ft_ssl> ");
	i = read(0, buf, 10000);
	if (i <= 0)
		return (NULL);
	buf[i] = 0;
	transform_line(buf);
	arg = ft_strsplit(buf, -1);
	i = -1;
	while (arg && arg[++i])
		;
	!arg ? i++ : 0;
	new_arg = malloc(sizeof(char*) * (i + 2));
	i2 = 0;
	new_arg[0] = (char*)arg;
	while (++i2 <= i)
		new_arg[i2] = arg[i2 - 1];
	new_arg[i2] = NULL;
	free(arg);
	return (new_arg);
}

int		main(int ac, char **av)
{
	t_ssl	s;
	int		n;
	char	**arg;

	n = 1;
	(void)ac;
	s.little_endian = *(char*)&n;
	arg = av;
	if (ac <= 1)
		while ((arg = pars_stdin_argument()))
		{
			arg[0] ? parsing(arg, &s) : 0;
			arg[0] = ft_strdup("caca");
			free_ancien(arg);
		}
	else
		parsing(arg, &s);
	return (1);
}
