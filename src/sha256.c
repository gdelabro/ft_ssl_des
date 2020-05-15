#include "../ssl_des.h"

static const unsigned int g_k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void			sha256_init(t_ssl *s, t_sha256 *sha, char *message)
{
	sha->a0 = !ft_strcmp(s->hash_name, "SHA256") ? 0x6a09e667 : 0xc1059ed8;
	sha->b0 = !ft_strcmp(s->hash_name, "SHA256") ? 0xbb67ae85 : 0x367cd507;
	sha->c0 = !ft_strcmp(s->hash_name, "SHA256") ? 0x3c6ef372 : 0x3070dd17;
	sha->d0 = !ft_strcmp(s->hash_name, "SHA256") ? 0xa54ff53a : 0xf70e5939;
	sha->e0 = !ft_strcmp(s->hash_name, "SHA256") ? 0x510e527f : 0xffc00b31;
	sha->f0 = !ft_strcmp(s->hash_name, "SHA256") ? 0x9b05688c : 0x68581511;
	sha->g0 = !ft_strcmp(s->hash_name, "SHA256") ? 0x1f83d9ab : 0x64f98fa7;
	sha->h0 = !ft_strcmp(s->hash_name, "SHA256") ? 0x5be0cd19 : 0xbefa4fa4;
	sha->nb_grps = 1 + (s->len + 8) / 64;
	if (!(sha->msg = malloc(64 * sha->nb_grps)))
		quit("malloc failed\n");
	ft_bzero(sha->msg, 64 * sha->nb_grps);
	memcpy(sha->msg, message, s->len);
	sha->size = s->len * 8;
	sha->size = (size_t)switch_endian(sha->size) << 32
		| (size_t)switch_endian(sha->size) >> 32;
	sha->msg[s->len] = 0x80;
	memcpy(sha->msg + (64 * sha->nb_grps) - 8, &(sha->size), 8);
	sha->grp = -1;
}

void			sha256_compression(t_sha256 *sha)
{
	sha->m = (unsigned int*)(sha->msg + sha->grp * 64);
	ft_memcpy(&(sha->a), &(sha->a0), 8 * sizeof(unsigned int));
	while (++sha->i < 64)
	{
		sha->w[sha->i] = sha->i < 16 ? switch_endian(sha->m[sha->i]) :
			(O1(sha->w[sha->i - 2]) + sha->w[sha->i - 7]
			+ O0(sha->w[sha->i - 15]) + sha->w[sha->i - 16]);
		sha->t1 = sha->h + E1(sha->e) +
			CH(sha->e, sha->f, sha->g) + g_k[sha->i] + sha->w[sha->i];
		sha->t2 = E0(sha->a) + MAJ(sha->a, sha->b, sha->c);
		sha->h = sha->g;
		sha->g = sha->f;
		sha->f = sha->e;
		sha->e = sha->d + sha->t1;
		sha->d = sha->c;
		sha->c = sha->b;
		sha->b = sha->a;
		sha->a = sha->t1 + sha->t2;
	}
}

void			sha256_funct(char *message, t_ssl *ssl)
{
	t_sha256	sha;

	sha256_init(ssl, &sha, message);
	while (++sha.grp < sha.nb_grps)
	{
		sha.i = -1;
		sha256_compression(&sha);
		sha.a0 += sha.a;
		sha.b0 += sha.b;
		sha.c0 += sha.c;
		sha.d0 += sha.d;
		sha.e0 += sha.e;
		sha.f0 += sha.f;
		sha.g0 += sha.g;
		sha.h0 += sha.h;
	}
	ssl->size_hash = !ft_strcmp(ssl->hash_name, "SHA256") ? 8 : 7;
	ssl->hash[0] = sha.a0;
	ssl->hash[1] = sha.b0;
	ssl->hash[2] = sha.c0;
	ssl->hash[3] = sha.d0;
	ssl->hash[4] = sha.e0;
	ssl->hash[5] = sha.f0;
	ssl->hash[6] = sha.g0;
	ssl->hash[7] = sha.h0;
}
