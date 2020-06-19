/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/19 20:05:04 by gdelabro          #+#    #+#             */
/*   Updated: 2020/06/19 21:46:57 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include <unistd.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <inttypes.h>
# include "ft_printf/ft_printf.h"
# include "ssl_des.h"

typedef struct s_ssl	t_ssl;

typedef struct	s_md5
{
	int				a0;
	int				b0;
	int				c0;
	int				d0;
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
	char			*msg;
	int				nb_grps;
	int				q;
	size_t			size;
	int				grp;
	int				i;
	unsigned int	*m;
	int				f;
	int				g;
}				t_md5;

typedef struct	s_sha256
{
	unsigned int	w[64];
	uint32_t		a0;
	uint32_t		b0;
	uint32_t		c0;
	uint32_t		d0;
	uint32_t		e0;
	uint32_t		f0;
	uint32_t		g0;
	uint32_t		h0;
	uint32_t		t1;
	uint32_t		t2;
	char			*msg;
	int				nb_grps;
	size_t			size;
	int				grp;
	int				i;
	unsigned int	*m;
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
	unsigned int	d;
	unsigned int	e;
	unsigned int	f;
	unsigned int	g;
	unsigned int	h;
}				t_sha256;

typedef struct	s_b64
{
	uint8_t			*msg;
	uint8_t			*result;
	unsigned int	size_result;
	int				len;
	int				fd;
	int				fd2;
	struct stat		st;
	char			buf[501];
	char			*tmp;
	int				i;
	uint32_t		nb;
	uint8_t			n[4];
	int				index;
}				t_b64;

typedef struct	s_des
{
	uint8_t			cbc;
	uint8_t			*msg;
	uint32_t		len;
	uint8_t			*result;
	uint32_t		size_result;
	int				fd;
	int				fd2;
	struct stat		st;
	char			buf[501];
	char			*tmp;
	int				i;
	uint32_t		nb;
	uint8_t			n[4];
	int				index;
	char			*pass;
	uint64_t		salt;
	uint64_t		key;
	uint64_t		iv;
	uint64_t		k[17];
	uint32_t		c[17];
	uint32_t		d[17];
	uint64_t		m;
	uint64_t		ip;
	uint32_t		l[17];
	uint32_t		r[17];
}				t_des;

struct			s_ssl
{
	int		d;
	int		e;
	char	*i;
	char	*o;
	int		p;
	int		q;
	int		r;
	int		a;
	char	*k;
	char	*pass;
	char	*v;
	char	*s;
	char	*file;
	char	*file_content;
	char	*input;
	void	(*hash_func)(char *, t_ssl *);
	int		size_hash;
	int		hash[8];
	char	hash_name[32];
	int		len;
	int		little_endian;
	int		ssl_command_type;
};

void			quit(char *str);

void			parsing(char **av, t_ssl *s);
void			hash_commands(char *str, t_ssl *s, char **av);
void			cipher_commands(char *str, t_ssl *s, char **av);

void			hashing(t_ssl *s);

void			md5_funct(char *message, t_ssl *ssl);
void			sha256_funct(char *message, t_ssl *ssl);
unsigned int	switch_endian(unsigned int nb);
unsigned int	rotl(unsigned int nb, unsigned int rot);
unsigned int	rotr(unsigned int nb, unsigned int rot);
uint64_t		reverse_uint64(uint64_t nb);

void			base64(t_ssl *s);
void			base64_decode(t_ssl *s, t_b64 *b);
void			aff_code(char *str, int fd);

void			des_init(char *str, t_ssl *s);
void			des_func(t_ssl *ssl, t_des *d);
void			base64_des(t_ssl *s, t_des *d);

void			create_subkeys(t_des *d);
uint64_t		permutate(uint64_t key, const uint8_t *tab,
							int oldkeyl, int keyl);

uint32_t		ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t		maj(uint32_t x, uint32_t y, uint32_t z);
uint32_t		e0(uint32_t x);
uint32_t		e1(uint32_t x);
uint32_t		o0(uint32_t x);
uint32_t		o1(uint32_t x);

#endif
