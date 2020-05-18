#include "../ssl_des.h"

static const uint8_t d[] = {
	66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
	54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
	29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
	66,66,66,66,66,66
};

void	calc_size_result(t_ssl *s, t_b64 *b)
{
	int		i;
	int		size;
	int		equals;
	char	c;

	i = -1;
	size = 0;
	equals = 0;
	while (++i < s->len)
	{
		c = b->msg[i];
		if (c == '=')
			equals++;
		else if (c == ' ' || c == '\n' || c == '\t')
			continue ;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
				|| (c >= '0' && c <= '9') || c == '+' || c == '/' ||  c == '=')
			size++;
		else
			quit("bad charactere in decode mode");
	}
	b->size_result = (size / 4) * 3 - equals;
	size % 4 || equals > 2 ? quit("bad decode format") : 0;
	!(b->result = malloc(b->size_result + 1)) ? quit("malloc failed") : 0;
	b->result[b->size_result] = 0;
}

void	base64_decode(t_ssl *s, t_b64 *b)
{
	int			i;
	uint32_t	i2;
	char		c;

	i = -1;
	i2 = 0;
	calc_size_result(s, b);
	while (i2 < b->size_result)
	{
		b->i = 0;
		b->nb = 0;
		while (b->i != 4 && ++i < s->len)
		{
			c = b->msg[i];
			if (c == ' ' || c == '\n' || c == '\t')
				continue ;
			b->nb = (b->nb << 6) + d[(uint8_t)c];
			b->i++;
		}
		b->result[i2++] = (uint8_t)(b->nb >> 16);
		i2 < b->size_result ? b->result[i2++] = (uint8_t)(b->nb >> 8) : 0;
		i2 < b->size_result ? b->result[i2++] = (uint8_t)b->nb : 0;
	}
	write(b->fd2, b->result, b->size_result);
}
