#include "../ft_ssl.h"

void	hash_arg(t_ssl *s, char **av)
{
	int i;

	i = 1;
	while (av[++i])
	{
		if (!ft_strcmp(av[i], "-p"))
			s->p = 1;
		else if (!ft_strcmp(av[i], "-r"))
			s->r = 1;
		else if (!ft_strcmp(av[i], "-q"))
			s->q = 1;
		else if (!ft_strcmp(av[i], "-s") && !s->s)
			!(s->s = av[++i]) ? quit("option s has no string") : 0;
		else if (ft_strcmp(av[i], "-s"))
			!s->file ? s->file = av[i] : 0;
	}
}

void	hash_commands(char *str, t_ssl *s, char **av)
{
	if (!ft_strcmp(str, "md5"))
	{
		ft_memcpy(s->hash_name, "MD5", 4);
		s->hash_func = &md5_funct;
	}
	else if (!ft_strcmp(str, "sha256"))
	{
		ft_memcpy(s->hash_name, "SHA256", 7);
		s->hash_func = &sha256_funct;
	}
	else if (!ft_strcmp(str, "sha224"))
	{
		ft_memcpy(s->hash_name, "SHA224", 7);
		s->hash_func = &sha256_funct;
	}
	hash_arg(s, av);
	hashing(s);
}
