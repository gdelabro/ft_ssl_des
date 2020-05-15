#include "../ssl_des.h"

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
	base64(s);
}

void	cipher_commands(char *str, t_ssl *s, char **av)
{
	if (!ft_strcmp(str, "base64"))
	{
		ft_memcpy(s->hash_name, "BASE64", 7);
		base64_arg(s, av);
	}
}
