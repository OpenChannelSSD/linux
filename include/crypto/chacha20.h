/*
 * Common values for the ChaCha20 algorithm
 */

#ifndef _CRYPTO_CHACHA20_H
#define _CRYPTO_CHACHA20_H

#include <crypto/skcipher.h>
#include <linux/types.h>
#include <linux/crypto.h>

#define CHACHA20_IV_SIZE	16
#define CHACHA20_KEY_SIZE	32
#define CHACHA20_BLOCK_SIZE	64

struct chacha20_ctx {
	u32 key[8];
};

void chacha20_block(u32 *state, void *stream);
void crypto_chacha20_init(u32 *state, struct chacha20_ctx *ctx, u8 *iv);
int crypto_chacha20_setkey(struct crypto_skcipher *tfm, const u8 *key,
			   unsigned int keysize);
int crypto_chacha20_crypt(struct skcipher_request *req);

#endif
