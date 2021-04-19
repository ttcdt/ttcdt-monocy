/*

    ttcdt-monocy - Tool for asymmetric encryption of files using monocypher

    ttcdt <dev@triptico.com>

    This software is released into the public domain.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "monocypher.h"

#define VERSION "1.03"

//#define DEBUG


int random_fill(uint8_t *buf, int z)
{
    int ret = 0;
    FILE *f;

    if ((f = fopen("/dev/urandom", "rb")) != NULL) {
        fread(buf, z, 1, f);
        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) cannot read from random device\n", ret);
    }

    return ret;
}


#ifdef DEBUG
void debug_hex(char *lbl, uint8_t *p, int size)
{
    int n;

    fprintf(stderr, "%6s: ", lbl);
    for (n = 0 ; n < size; n++)
        fprintf(stderr, "%02x", p[n]);
    fprintf(stderr, "\n");
}
#else /* DEBUG */
#define debug_hex(l, p, s) ;
#endif /* DEBUG */


int read_key_file(uint8_t *p, int size, char *fn)
/* reads a one-line hexadecimal text file into buffer */
{
    int ret = 0;
    FILE *f;

    if ((f = fopen(fn, "r")) != NULL) {
        int n, c;

        for (n = 0; n < size; n++) {
            fscanf(f, "%02x", &c);
            p[n] = c;
        }

        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) cannot read key file\n", ret);
    }

    return ret;
}


int write_key_file(uint8_t *p, int size, char *fn)
/* writes a buffer as a one-line hexadecimal text file */
{
    int ret = 0;
    FILE *f; 

    if ((f = fopen(fn, "w")) != NULL) {
        int n;

        for (n = 0; n < size; n++)
            fprintf(f, "%02x", p[n]);
        fprintf(f, "\n");

        fclose(f);
    }
    else {
        ret = 3;
        fprintf(stderr, "ERROR: (%d) cannot write key file\n", ret);
    }

    return ret;
}


int generate_keys(char *pk_fn, char *sk_fn)
{
    uint8_t sk[32];     /* secret key */
    uint8_t pk[32];     /* public key */

    random_fill(sk, sizeof(sk));
    crypto_key_exchange_public_key(pk, sk);

    /* write the secret and public keys */
    return write_key_file(sk, sizeof(sk), sk_fn) +
           write_key_file(pk, sizeof(pk), pk_fn);
}


int rebuild_public_key(char *pk_fn, char *sk_fn)
{
    int ret = 0;
    uint8_t sk[32];     /* secret key */
    uint8_t pk[32];     /* public key */

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) == 0) {
        /* recompute public key */
        crypto_key_exchange_public_key(pk, sk);

        /* write it */
        ret = write_key_file(pk, sizeof(pk), pk_fn);
    }

    return ret;
}


void hash_key(uint8_t *salt, uint8_t *h_key, uint8_t *key, int size)
{
    uint8_t *work_area;

    work_area = (uint8_t *)malloc(100000 * 1024);

    crypto_argon2i(h_key, 32, work_area, 100000, 3, key, size, salt, 16);

    free(work_area);
}


#define BLOCK_SIZE 1024 * 1024

int encrypt(FILE *i, FILE *o, char *pk_fn)
{
    int ret = 0;
    uint8_t pk[32];     /* public key */
    uint8_t tmp_pk[32]; /* temporary public key */
    uint8_t tmp_sk[32]; /* temporary secret key */
    uint8_t key[32];    /* stream key */
    uint8_t cy_key[32]; /* encrypted stream key */
    uint8_t ss[32];     /* shared secret */
    uint8_t h_ss[32];   /* hashed shared secret (key to stream key) */
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t salt[16];
    uint8_t *bl;
    int z;

    bl = (uint8_t *)malloc(BLOCK_SIZE);

    if ((ret = read_key_file(pk, sizeof(pk), pk_fn)) != 0)
        goto end;

    /* create a disposable set of assymmetric keys:
       the public one shall be inside the encrypted stream
       aside with the encrypted symmetric key */
    random_fill(tmp_sk, sizeof(tmp_sk));
    crypto_key_exchange_public_key(tmp_pk, tmp_sk);

    /* create a nonce for the encryption of the stream key */
    random_fill(nonce, sizeof(nonce));

    /* create the stream key */
    random_fill(key, sizeof(key));

    /* pick the shared secret */
    crypto_key_exchange(ss, tmp_sk, pk);

    debug_hex("pk",     pk,     sizeof(pk));
    debug_hex("tmp_pk", tmp_pk, sizeof(tmp_pk));
    debug_hex("nonce",  nonce,  sizeof(nonce));
    debug_hex("ss",     ss,     sizeof(ss));

    /* create a salt to hash the shared secret */
    random_fill(salt, sizeof(salt));

    debug_hex("salt", salt, sizeof(salt));

    /* hash the shared secret to use it to encrypt the stream key */
    hash_key(salt, h_ss, ss, sizeof(ss));
    crypto_wipe(ss, sizeof(ss));

    debug_hex("h_ss", h_ss, sizeof(ss));
    debug_hex("key",  key,  sizeof(key));

    /* encrypt the stream key using the hashed shared secret as key */
    crypto_lock(mac, cy_key, h_ss, nonce, key, sizeof(key));

    debug_hex("mac",    mac,    sizeof(mac));
    debug_hex("cy_key", cy_key, sizeof(cy_key));

    /** start of output **/

    /* write the signature */
    bl[0] = 'n';
    bl[1] = 'a';
    bl[2] = 0x00;
    bl[3] = 0x10;
    fwrite(bl, 4, 1, o);

    /* write the disposable pk */
    fwrite(tmp_pk, sizeof(tmp_pk), 1, o);

    /* write the nonce */
    fwrite(nonce, sizeof(nonce), 1, o);

    /* write the mac */
    fwrite(mac, sizeof(mac), 1, o);

    /* write the salt */
    fwrite(salt, sizeof(salt), 1, o);

    /* write the encrypted stream key */
    fwrite(cy_key, sizeof(cy_key), 1, o);

    /* read by blocks */
    while ((z = fread(bl, 1, BLOCK_SIZE, i)) > 0) {
        random_fill(nonce, sizeof(nonce));
        crypto_lock(mac, bl, key, nonce, bl, z);

        debug_hex("nonce", nonce, sizeof(nonce));
        debug_hex("mac",   mac,   sizeof(mac));
        debug_hex("bl",    bl,    z);

        if (fwrite(nonce, sizeof(nonce), 1, o) != 1) {
            ret = 3;
            fprintf(stderr, "ERROR: (%d) write error (nonce)\n", ret);
            break;
        }

        if (fwrite(mac, sizeof(mac), 1, o) != 1) {
            ret = 3;
            fprintf(stderr, "ERROR: (%d) write error (mac)\n", ret);
            break;
        }

        if (fwrite(bl, 1, z, o) != z) {
            ret = 3;
            fprintf(stderr, "ERROR: (%d) write error (block)\n", ret);
            break;
        }
    }
 
end:
    free(bl);

    return ret;
}


int decrypt(FILE *i, FILE *o, char *sk_fn)
{
    int ret = 0;
    uint8_t tmp_pk[32]; /* temporary public key */
    uint8_t sk[32];     /* secret key */
    uint8_t cy_key[32]; /* encrypted stream key */
    uint8_t key[32];    /* stream key */
    uint8_t ss[32];     /* the shared secret */
    uint8_t h_ss[32];   /* hashed shared secret (key to stream key) */
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t salt[16];
    uint8_t *bl;
    int z;

    bl = (uint8_t *)malloc(BLOCK_SIZE);

    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) != 0)
        goto end;

    /* read 4 bytes */
    if (fread(bl, 4, 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) unexpected EOF reading signature\n", ret);
        goto end;
    }

    /* valid signature? */
    if (bl[0] == 'n' && bl[1] == 'a' && bl[2] == 0x00) {
        if (bl[3] != 0x10) {
            ret = 4;
            fprintf(stderr, "ERROR: (%d) signature for another format (%02X)\n", ret, bl[3]);
            goto end;
        }
    }
    else {
        ret = 4;
        fprintf(stderr, "ERROR: (%d) bad signature\n", ret);
        goto end;
    }

    /* read the public key + the nonce + the mac + encrypted symmetric key */
    if (fread(tmp_pk, sizeof(tmp_pk), 1, i) != 1 ||
        fread(nonce,  sizeof(nonce),  1, i) != 1 ||
        fread(mac,    sizeof(mac),    1, i) != 1 ||
        fread(salt,   sizeof(salt),   1, i) != 1 ||
        fread(cy_key, sizeof(cy_key), 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: (%d) unexpected EOF reading header\n", ret);
        goto end;
    }

    debug_hex("tmp_pk", tmp_pk, sizeof(tmp_pk));
    debug_hex("nonce",  nonce,  sizeof(nonce));
    debug_hex("mac",    mac,    sizeof(mac));
    debug_hex("salt",   salt,   sizeof(salt));
    debug_hex("cy_key", cy_key, sizeof(cy_key));

    /* pick the shared secret */
    crypto_key_exchange(ss, sk, tmp_pk);

    debug_hex("ss", ss, sizeof(ss));

    /* hash the shared secret to use it to decrypt the stream key */
    hash_key(salt, h_ss, ss, sizeof(ss));
    crypto_wipe(ss, sizeof(ss));
    crypto_wipe(sk, sizeof(sk));

    debug_hex("h_ss", h_ss, sizeof(ss));

    /* decrypt the stream key using the hashed shared secret as key */
    if (crypto_unlock(key, h_ss, nonce, mac, cy_key, sizeof(cy_key))) {
        ret = 4;
        fprintf(stderr, "ERROR: (%d) corrupted header\n", ret);
        goto end;
    }

    debug_hex("key", key, sizeof(key));

    /* read by blocks */
    while (fread(nonce, sizeof(nonce), 1, i) == 1 &&
           fread(mac, sizeof(mac), 1, i) == 1 &&
           (z = fread(bl, 1, BLOCK_SIZE, i)) > 0) {

        debug_hex("nonce", nonce, sizeof(nonce));
        debug_hex("mac",   mac,   sizeof(mac));
        debug_hex("bl",    bl,    z);

        if (crypto_unlock(bl, key, nonce, mac, bl, z)) {
            ret = 4;
            fprintf(stderr, "ERROR: (%d) corrupted stream\n", ret);
            goto end;
        }

        if (fwrite(bl, 1, z, o) != z) {
            ret = 3;
            fprintf(stderr, "ERROR: (%d) write error\n", ret);
            break;
        }
    }

end:
    free(bl);

    return ret;
}


char *usage_str="\
ttcdt <dev@triptico.com>\n\
This software is released into the public domain.\n\
\n\
Usage:\n\
\n\
  ttcdt-monocy -G -p pubkey -s seckey     Generate key pairs\n\
  ttcdt-monocy -R -p pubkey -s seckey     Regenerate pubkey from seckey\n\
  ttcdt-monocy -E -p pubkey               Encrypt STDIN to STDOUT\n\
  ttcdt-monocy -D -s seckey               Decrypt STDIN to STDOUT\n\
\n\
Examples:\n\
 (on desktop)\n\
 $ ttcdt-monocy -G -p ~/.key.pub -s ~/.key.sec\n\
 $ scp ~/.key.pub server:~/.key.pub\n\
 (on server, secret key not needed there)\n\
 $ (cd / && sudo tar czvf - etc/) | ttcdt-monocy -E -p ~/.key.pub > encrypted\n\
 (back on desktop, to restore)\n\
 $ ttcdt-monocy -D -s ~/.key.sec < encrypted > decrypted.tar.gz\n\
\n\
Algorithms: Curve25519, Argon2i, Chacha20+Poly1305.";

int usage(void)
{
    fprintf(stderr,
        "ttcdt-monocy %s - Tool for asymmetric encryption of files using monocypher\n",
        VERSION);
    fprintf(stderr, "%s\n", usage_str);

    return 1;
}


int init(void)
{
    return 0;
}


int main(int argc, char *argv[])
{
    int ret;
    char *pk_fn = NULL;
    char *sk_fn = NULL;
    char *cmd = NULL;

    if (!init()) {
        int n;

        for (n = 1; n < argc; n++) {
            char *p = argv[n];

            if (strcmp(p, "-G") == 0 || strcmp(p, "-R") == 0 ||
                strcmp(p, "-E") == 0 || strcmp(p, "-D") == 0)
                cmd = p;
            else
            if (strcmp(p, "-p") == 0)
                pk_fn = argv[++n];
            else
            if (strcmp(p, "-s") == 0)
                sk_fn = argv[++n];
        }

        if (cmd == NULL)
            ret = usage();
        else
        if (strcmp(cmd, "-G") == 0 && pk_fn && sk_fn)
            ret = generate_keys(pk_fn, sk_fn);
        else
        if (strcmp(cmd, "-R") == 0 && pk_fn && sk_fn)
            ret = rebuild_public_key(pk_fn, sk_fn);
        else
        if (strcmp(cmd, "-E") == 0 && pk_fn)
            ret = encrypt(stdin, stdout, pk_fn);
        else
        if (strcmp(cmd, "-D") == 0 && sk_fn)
            ret = decrypt(stdin, stdout, sk_fn);
        else
            ret = usage();
    }
    else {
        ret = 4;
        fprintf(stderr, "ERROR: (%d) cannot initialize crypto library\n", ret);
    }

    return ret;
}
