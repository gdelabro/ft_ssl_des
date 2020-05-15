#include "../ssl_des.h"

void	determin_ssl_func(char *str, t_ssl *s, char **av)
{
	if (!ft_strcmp(str, "md5") || !ft_strcmp(str, "sha256")
		|| !ft_strcmp(str, "sha224"))
		s->ssl_command_type = 1;
	if (!ft_strcmp(str, "base64"))
		s->ssl_command_type = 2;
	s->ssl_command_type == 1 ? hash_commands(str, s, av) : 0;
	s->ssl_command_type == 2 ? cipher_commands(str, s, av) : 0;
	if (!s->ssl_command_type)
		quit("invalid ssl command\n");
}

void	parsing(char **av, t_ssl *s)
{
	if (!av[1])
		quit("no ssl command selected\n");
	ft_bzero(s, sizeof(t_ssl));
	determin_ssl_func(av[1], s, av);
}
