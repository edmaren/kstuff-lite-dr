#include <stddef.h>
#include <stdint.h>

#include <isa-l_crypto/aes_cbc.h>
#include <isa-l_crypto/aes_keyexp.h>
#include <isa-l_crypto/aes_xts.h>
#include <isa-l_crypto/isal_crypto_api.h>

void _aes_keyexp_128_avx(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec);
void _aes_cbc_dec_128_avx(void *in, uint8_t *iv, uint8_t *keys, void *out, uint64_t len_bytes);
void _XTS_AES_128_enc_expanded_key_avx(uint8_t *k2, uint8_t *k1, uint8_t *initial_tweak,
                                       uint64_t len_bytes, const uint8_t *in, uint8_t *out);
void _XTS_AES_128_dec_expanded_key_avx(uint8_t *k2, uint8_t *k1, uint8_t *initial_tweak,
                                       uint64_t len_bytes, const uint8_t *in, uint8_t *out);

int
isal_aes_keyexp_128(const uint8_t *key, uint8_t *exp_key_enc, uint8_t *exp_key_dec)
{
        if (key == NULL)
                return ISAL_CRYPTO_ERR_NULL_KEY;
        if (exp_key_enc == NULL || exp_key_dec == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;

        _aes_keyexp_128_avx(key, exp_key_enc, exp_key_dec);

        return 0;
}

int
isal_aes_cbc_dec_128(const void *in, const void *iv, const void *keys, void *out,
                     const uint64_t len_bytes)
{
        if (keys == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (iv == NULL)
                return ISAL_CRYPTO_ERR_NULL_IV;
        if ((len_bytes & 0xf) != 0)
                return ISAL_CRYPTO_ERR_CIPH_LEN;

        _aes_cbc_dec_128_avx((void *) in, (uint8_t *) iv, (uint8_t *) keys, out, len_bytes);

        return 0;
}

int
isal_aes_xts_enc_128_expanded_key(const uint8_t *k2, const uint8_t *k1,
                                  const uint8_t *initial_tweak, const uint64_t len_bytes,
                                  const void *in, void *out)
{
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;
        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;

        _XTS_AES_128_enc_expanded_key_avx((uint8_t *) k2, (uint8_t *) k1,
                                          (uint8_t *) initial_tweak, len_bytes, in, out);

        return 0;
}

int
isal_aes_xts_dec_128_expanded_key(const uint8_t *k2, const uint8_t *k1,
                                  const uint8_t *initial_tweak, const uint64_t len_bytes,
                                  const void *in, void *out)
{
        if (k2 == NULL || k1 == NULL)
                return ISAL_CRYPTO_ERR_NULL_EXP_KEY;
        if (initial_tweak == NULL)
                return ISAL_CRYPTO_ERR_XTS_NULL_TWEAK;
        if (in == NULL)
                return ISAL_CRYPTO_ERR_NULL_SRC;
        if (out == NULL)
                return ISAL_CRYPTO_ERR_NULL_DST;
        if (len_bytes < ISAL_AES_XTS_MIN_LEN || len_bytes > ISAL_AES_XTS_MAX_LEN)
                return ISAL_CRYPTO_ERR_CIPH_LEN;

        _XTS_AES_128_dec_expanded_key_avx((uint8_t *) k2, (uint8_t *) k1,
                                          (uint8_t *) initial_tweak, len_bytes, in, out);

        return 0;
}
