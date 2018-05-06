/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include "config.h"

//#define RSA_DEBUG
#if defined(POLARSSL_RSA_C)

#include "rsa.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef POLARSSL_SELF_TEST
/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

#else
/*
 * Default RSA-1024 keypair.
 * If project need special keypair, Please replace the follow define.
 * add by wwqing 2014-12-08
 */
#define KEY_LEN 256

#define RSA_N   "ed4e7d50e15bde98a5e776bb676b3ec41e51272386e8f712594f4fd41711f8bf0c7fb0dece5859a8fe0b4f1d6ca6c87a9f6487fd5a954851ffe79fc0206b323648e83b7223bfa9ba8a5c9fed1230a1e85410a54a1e457cedb23e312497d2f15125e59fb311fae09996dd1de64f29cfaea512584274ae05a956e98f3182254447362a8841b4a84e0c3bfdb50d5b23c1aa523e9486d1347c587711a1f12f2066a75f788b1a543da9f847472ed91bf11b07f60927bd13d3d2aecbc9ffd0f977cf6c115127ee02dd6bec7627f4f5168f7cb467caf42aaafddc9c24bf52663133ae52a701b44556f19b2a04bfc337f7c08ecf297ae3cee35f26e151b383752a4a6f25"
#define RSA_E   "03"
#ifndef PUBLIC_KEY_ONLY
#define RSA_D   "9e34538b40e7e9bb1944f9d244f229d814361a17af45fa0c3b8a35380f61507f5daa75e9dee5911b54078a139dc485a714edaffe3c63858bffefbfd56af2217985f027a16d2a712706e86a9e0c206bf0380b18dc142e5349217ecb6dba8ca0e0c3ee6a776151eb110f3e13eedf71351f18b6e581a31eae70e49bb4cbac18d82e30bb163874e07e063c19cbcc1d1852144d0723e8d984fa48b97d695b57a6d7bce4521569d9fa479997b8297390f23ccd87590d6a7dfbd7708f598992ba85abcd6cb3770053c1553918df46cdd9fc31482710eb8b778924e5a8c5291de73591875ecb7907a58d14b9c22d97af04a457477e92be9633d26a78a4a69bfdb442e2f3"
#define RSA_P   "fbeb8a2384e92683993c39b29457889a95c80966a5b93e61f50980423736c891adade0228bf08390f2a0e2ffcd879a017e9cee67520192ea9d6986a19b2ad65da0cd660761106cec4513ca6321f5d81413b1c4b552db70f54e6aae80882948074d6cd28483e1f6e08b8c3d32563532dec2bbac1b90b2ea21a519be5d686247f7"
#define RSA_Q   "f1265cc9806e6a7f489ac9a89b27bdf148ebd542e533c6896bcc03a5f46f5a7a5b4f8ad90155bb00f1120dabf4fe25d22c66a53604d87c9b575a2ad34684775a4d768f66242aff2a8bc5405d2d9f5ab4197fce2424d4b44e592ce638ce3a0c004b63ac355abc0532d5ef227f1a94d90528e319d204f09d0ab59fdb1b3383d2c3"
#define RSA_DP  "a7f25c17adf0c457bb7d7bcc62e505bc63dab0ef19262996a35baad6cf79db0bc91e956c5d4b0260a1c0975533afbc00ff13499a36abb747139baf166771e43e6b33995a40b59df2d8b7dc4216a3e562b7cbd878e1e7a0a3899c7455b01b855a339de1adad414f405d0828cc3978cc9481d272bd0b21f16bc3667ee8f041854f"
#define RSA_DQ  "a0c43ddbaaf446ff85bc8670676fd3f6309d38d74377d9b0f288026ea2f4e6fc3cdfb1e600e3d200a0b6b3c7f8a96e8c1d99c379589053123a3c1c8cd9ada4e6de4f0a44181caa1c5d2e2ae8c914e722bbaa896d6de322dee61deed0897c0800324272ce3c7d58cc8e9f6c54bc633b58c5ecbbe158a068b1ce6a92122257e1d7"
#define RSA_QP  "010530bf78b4ad9c3c06e1724687cd66b4afc9718b90da0cec9474d0f1b8b92c71d6fcd904b285d54ea3cb384307273c10680daddef94c553d8333d992e8ff54b329bc1f2294276cad06ded6e9aad4662c36d938fe1c1a1318ea4b2fb44d1a64225d63be4b46b6616410996c8d3cbd2f95902cae5300ea7a819493e8e23ab944"
#endif
#endif

/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( rsa_context ) );

    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

#if defined(POLARSSL_GENPRIME)

/*
 * Generate an RSA keypair
 */
int rsa_gen_key( rsa_context *ctx,
        int (*f_rng)(void *),
        void *p_rng,
        int nbits, int exponent )
{
    int ret;
    mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &P1, &Q1, &H, &G, NULL );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MPI_CHK( mpi_lset( &ctx->E, exponent ) );

    do
    {
        MPI_CHK( mpi_gen_prime( &ctx->P, ( nbits + 1 ) >> 1, 0, 
                                f_rng, p_rng ) );

        MPI_CHK( mpi_gen_prime( &ctx->Q, ( nbits + 1 ) >> 1, 0,
                                f_rng, p_rng ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MPI_CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mpi_msb( &ctx->N ) != nbits )
            continue;

        MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:

    mpi_free( &G, &H, &Q1, &P1, NULL );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED | ret );
    }

    return( 0 );   
}

#endif

/*
 * Check a public RSA key
 */
int rsa_check_pubkey( const rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 || 
        ( ctx->E.p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > 4096 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_msb( &ctx->E ) > 64 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int rsa_check_privkey( const rsa_context *ctx )
{
    int ret;
    mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2;
	
    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );
	
    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );
	
    mpi_init( &PQ, &DE, &P1, &Q1, &H, &I, &G, &G2, &L1, &L2, NULL );
    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
    MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );  
    MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mpi_cmp_mpi( &PQ, &ctx->N ) == 0 &&
        mpi_cmp_int( &L2, 0 ) == 0 &&
        mpi_cmp_int( &I, 1 ) == 0 &&
        mpi_cmp_int( &G, 1 ) == 0 )
    {
        mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, &G2, &L1, &L2, NULL );
        return( 0 );
    }

    
cleanup:

    mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, &G2, &L1, &L2, NULL );
    return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED | ret );
}

/*
 * Do an RSA public key operation
 */
int rsa_public( rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret, olen;
    mpi T;

    mpi_init( &T, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Do an RSA private key operation
 */
int rsa_private( rsa_context *ctx,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret, olen;
    mpi T, T1, T2;

    mpi_init( &T, &T1, &T2, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

#if 1
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * output = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );
#endif

    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, &T1, &T2, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED | ret );

    return( 0 );
}

/*
 * Add the message padding, then do an RSA operation
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int (*f_rng)(void *),
                       void *p_rng,
                       int mode, int  ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    int nb_pad, olen;
    unsigned char *p = output;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( ilen < 0 || olen < ilen + 11 || f_rng == NULL )
            {
                printf("rsa_pkcs1_encrypt POLARSSL_ERR_RSA_BAD_INPUT_DATA\n");
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            nb_pad = olen - 3 - ilen;

            *p++ = 0;
            *p++ = RSA_CRYPT;

            while( nb_pad-- > 0 )
            {
                int rng_dl = 100;

                do {
                    *p = (unsigned char) f_rng( p_rng );
                } while( *p == 0 && --rng_dl );

                // Check if RNG failed to generate data
                if( rng_dl == 0 )
                {
                    printf("rsa_pkcs1_encrypt POLARSSL_ERR_RSA_RNG_FAILED\n");
                    return POLARSSL_ERR_RSA_RNG_FAILED;
                }

                p++;
            }
            *p++ = 0;
            memcpy( p, input, ilen );
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, output, output ) );
}

/*
 * Do an RSA operation, then remove the message padding
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, int *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       int output_max_len)
{
    int ret, ilen;
    unsigned char *p;
    unsigned char buf[1024];

    ilen = ctx->len;

    if( ilen < 16 || ilen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_CRYPT )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + ilen - 1 )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    if (ilen - (int)(p - buf) > output_max_len)
    	return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (int)(p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Do an RSA operation to sign the message digest
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int mode,
                    int hash_id,
                    int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    int nb_pad, olen;
    unsigned char *p = sig;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            switch( hash_id )
            {
                case SIG_RSA_RAW:
                    nb_pad = olen - 3 - hashlen;
                    break;

                case SIG_RSA_MD2:
                case SIG_RSA_MD4:
                case SIG_RSA_MD5:
                    nb_pad = olen - 3 - 34;
                    break;

                case SIG_RSA_SHA1:
                    nb_pad = olen - 3 - 35;
                    break;

                case SIG_RSA_SHA224:
                    nb_pad = olen - 3 - 47;
                    break;

                case SIG_RSA_SHA256:
                    nb_pad = olen - 3 - 51;
                    break;

                case SIG_RSA_SHA384:
                    nb_pad = olen - 3 - 67;
                    break;

                case SIG_RSA_SHA512:
                    nb_pad = olen - 3 - 83;
                    break;


                default:
                    return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            if( nb_pad < 8 )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            *p++ = 0;
            *p++ = RSA_SIGN;
            memset( p, 0xFF, nb_pad );
            p += nb_pad;
            *p++ = 0;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case SIG_RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 2; break;

        case SIG_RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 4; break;

        case SIG_RSA_MD5:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 5; break;

        case SIG_RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;

        case SIG_RSA_SHA224:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 28 );
            p[1] += 28; p[14] = 4; p[18] += 28; break;

        case SIG_RSA_SHA256:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 32 );
            p[1] += 32; p[14] = 1; p[18] += 32; break;

        case SIG_RSA_SHA384:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 48 );
            p[1] += 48; p[14] = 2; p[18] += 48; break;

        case SIG_RSA_SHA512:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 64 );
            p[1] += 64; p[14] = 3; p[18] += 64; break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, sig, sig ) );
}

/*
 * Do an RSA operation and check the message digest
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      int hashlen,
                      const unsigned char *hash,
                      unsigned char *sig )
{
    int ret, len, siglen;
    unsigned char *p, c;
    unsigned char buf[1024];

    siglen = ctx->len;
    if( siglen < 16 || siglen > (int) sizeof( buf ) )
    {
        printf("[error] POLARSSL_ERR_RSA_BAD_INPUT_DATA\n");
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }
    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, sig, buf );

    if( ret != 0 )
    {
        return( ret );
    }
    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_SIGN )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + siglen - 1 || *p != 0xFF )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    len = siglen - (int)( p - buf );

    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );

        if( ( c == 2 && hash_id == SIG_RSA_MD2 ) ||
            ( c == 4 && hash_id == SIG_RSA_MD4 ) ||
            ( c == 5 && hash_id == SIG_RSA_MD5 ) )
        {
            if( memcmp( p + 18, hash, 16 ) == 0 ) 
                return( 0 );
            else
                return( POLARSSL_ERR_RSA_VERIFY_FAILED );
        }
    }

    if( len == 35 && hash_id == SIG_RSA_SHA1 )
    {
#ifdef RSA_DEBUG
		int i = 0;
		printf( "ASN1_HASH_SHA1 in memory:\n" );
	
		for(i = 0; i < 15; i++)
		{
			printf("%2.2x", p[i]);
		}
		printf("\n\n");

		printf( "ASN1_HASH_SHA1 Tag:\n" );
		{
			char tag[16] = {0};
			memcpy(tag, ASN1_HASH_SHA1, 15);
			for(i = 0; i < 15; i++)
			{
				printf("%2.2x", tag[i]);
			}
		}
		printf("\n\n");
	
		printf("verify sha1:\n");
		for(i = 15; i < (20+15); i++)
		{
			printf("%2.2x", p[i]);
		}
		printf("\n\n");
#endif	
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) == 0 &&
            memcmp( p + 15, hash, 20 ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }
	
    if( ( len == 19 + 28 && p[14] == 4 && hash_id == SIG_RSA_SHA224 ) ||
        ( len == 19 + 32 && p[14] == 1 && hash_id == SIG_RSA_SHA256 ) ||
        ( len == 19 + 48 && p[14] == 2 && hash_id == SIG_RSA_SHA384 ) ||
        ( len == 19 + 64 && p[14] == 3 && hash_id == SIG_RSA_SHA512 ) )
    {
    	c = p[1] - 17;
        p[1] = 17;
        p[14] = 0;

        if( p[18] == c &&
                memcmp( p, ASN1_HASH_SHA2X, 18 ) == 0 &&
                memcmp( p + 19, hash, c ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    if( len == hashlen && hash_id == SIG_RSA_RAW )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    return( POLARSSL_ERR_RSA_INVALID_PADDING );
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->RQ, &ctx->RP, &ctx->RN,
              &ctx->QP, &ctx->DQ, &ctx->DP,
              &ctx->Q,  &ctx->P,  &ctx->D,
              &ctx->E,  &ctx->N,  NULL );
}

//wwq add start
/*
 * Sign data
 * RsaType: SIG_RSA_RAW/SIG_RSA_MD5/SIG_RSA_SHA1, more info see rsa.h
 * uiData: data need to be sign;
 * uiDataLen: data length
 * sign: data sign by RSA1(output data)
 * signLen: data sign length
 * Return: ok, 0, fialed, 1.
 */
#ifndef PUBLIC_KEY_ONLY
int ras_sign(const int RsaType,
				const unsigned char* ucData, 
				const unsigned int uiDataLen,
				unsigned char* sign, 
				const unsigned int signLen)
{
	rsa_context rsa;
	unsigned char rsa_ciphertext[KEY_LEN];
	int i = 0;

	if((NULL == ucData) || (NULL == sign))
	{
		printf( "[ras_sign] Param ucData or sign is NULL!\n");
		return( 1 );
	}

#ifdef RSA_DEBUG
	printf( "[ras_sign] Param RsaType[%d](0-RAW,CRC; 4-MD5; 5-SHA1.) uiDataLen[%d], signLen[%d], ucData: \n", RsaType, uiDataLen, signLen );
	for(i = 0; i < uiDataLen; i++)
	{
		if((i != 0) && (i % 16 == 0))
			printf("\n");
		printf("%2.2x", ucData[i]);
	}
	printf("\n\n");
#endif

#if 1
	switch(RsaType)
	{
		case SIG_RSA_RAW:
		{
			if(uiDataLen != 4)
			{
				printf( "[ras_sign] Param uiDataLen[%d] error! CRC data should be 4.\n", uiDataLen );
				return( 1 );
			}
		}

		case SIG_RSA_MD5:
		{
			if(uiDataLen != 16)
			{
				printf( "[ras_sign] Param uiDataLen[%d] error! Md5 data should be 16.\n", uiDataLen );
				return( 1 );
			}
		}
		break;

		case SIG_RSA_SHA1:
		{
			if(uiDataLen != 20)
			{
				printf( "[ras_sign] Param uiDataLen[%d] error! SHA1 data should be 20.\n", uiDataLen );
				return( 1 );
			}
		}
		break;

		default:
			printf( "[ras_sign] Param RsaType[%d] error!\n", RsaType );
			return( 1 );
	}
#endif	

	if(signLen < KEY_LEN)
	{
		printf( "[ras_sign] Param signLen[%d] error! it should be >= %d\n", signLen, KEY_LEN );
		return( 1 );
	}

	rsa_init( &rsa, RSA_PKCS_V15, 0 );

	rsa.len = KEY_LEN;
	mpi_read_string( &rsa.N , 16, RSA_N  );
	mpi_read_string( &rsa.E , 16, RSA_E  );
	mpi_read_string( &rsa.D , 16, RSA_D  );
	mpi_read_string( &rsa.P , 16, RSA_P  );
	mpi_read_string( &rsa.Q , 16, RSA_Q  );
	mpi_read_string( &rsa.DP, 16, RSA_DP );
	mpi_read_string( &rsa.DQ, 16, RSA_DQ );
	mpi_read_string( &rsa.QP, 16, RSA_QP );

	if( rsa_check_privkey( &rsa ) != 0 )
	{
		printf( "[ras_sign] rsa_check_privkey failed\n" );
		return( 1 );
	}
	printf( "[ras_sign] rsa_check_privkey ok\n" );


	if( rsa_pkcs1_sign( &rsa, RSA_PRIVATE, RsaType, uiDataLen,
						ucData, rsa_ciphertext ) != 0 )
	{
		printf( "[ras_sign] rsa_pkcs1_sign failed\n" );
		return( 1 );
	}
	printf( "[ras_sign] rsa_pkcs1_sign ok\n" );

	memcpy(sign, rsa_ciphertext, signLen);
	
	rsa_free( &rsa );

	return( 0 );
}
#endif

/*
 * Verify data
 * RsaType: SIG_RSA_RAW/SIG_RSA_MD5/SIG_RSA_SHA1, more info see rsa.h
 * uiData: data need to be Verify;
 * uiDataLen: data length
 * sign: data signed by RSA1(Input data)
 * signLen: data sign length
 * Return: ok, 0, fialed, 1.
 */
int ras_verify(const int RsaType,
				const unsigned char* ucData, 
				const unsigned int uiDataLen,
				unsigned char* sign, 
				const unsigned int signLen)
{
	rsa_context rsa;
	int i = 0;

	if((NULL == ucData) || (NULL == sign))
	{
		printf( "[ras_verify] Param ucData or sign is NULL!\n");
		return( 1 );
	}
	
	printf( "[ras_verify] Param RsaType[%d](0-RAW,CRC; 4-MD5; 5-SHA1.) uiDataLen[%d], signLen[%d]\n", RsaType, uiDataLen, signLen );

#ifdef RSA_DEBUG
	printf( "ucData:\n" );

	for(i = 0; i < uiDataLen; i++)
	{
		printf("%2.2x", ucData[i]);
	}
	printf("\n\n");

	printf("sign:\n");
	for(i = 0; i < signLen; i++)
	{
		if((i != 0) && (i % 16 == 0))
			printf("\n");
		printf("%2.2x", sign[i]);
	}
	printf("\n\n");
#endif	

#if 1
	switch(RsaType)
	{
		case SIG_RSA_RAW:
		{
			if(uiDataLen != 4)
			{
				printf( "[ras_verify] Param uiDataLen[%d] error! CRC data should be 4.\n", uiDataLen );
				return( 1 );
			}
		}
		break;
		
		case SIG_RSA_MD5:
		{
			if(uiDataLen != 16)
			{
				printf( "[ras_verify] Param uiDataLen[%d] error! Md5 data should be 16.\n", uiDataLen );
				return( 1 );
			}
		}
		break;

		case SIG_RSA_SHA1:
		{
			if(uiDataLen != 20)
			{
				printf( "[ras_verify] Param uiDataLen[%d] error! SHA1 data should be 20.\n", uiDataLen );
				return( 1 );
			}
		}
		break;

		default:
			printf( "[ras_verify] Param RsaType[%d] error!\n", RsaType );
			return( 1 );
	}
#endif

	if(signLen < KEY_LEN)
	{
		printf( "[ras_verify] Param signLen[%d] error! it should be >= %d\n", signLen, KEY_LEN );
		return( 1 );
	}

	rsa_init( &rsa, RSA_PKCS_V15, 0 );

	rsa.len = KEY_LEN;
	mpi_read_string( &rsa.N , 16, RSA_N  );
	mpi_read_string( &rsa.E , 16, RSA_E  );

	if( rsa_check_pubkey( &rsa ) != 0 )
	{
		printf( "[ras_verify] rsa_check_pubkey failed\n" );
		return( 1 );
	}
	printf( "[ras_verify] rsa_check_pubkey ok\n" );


	if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, RsaType, uiDataLen,
							  ucData, sign ) != 0 )
	{
		printf( "[ras_verify] rsa_pkcs1_verify failed\n" );
		return( 1 );
	}	
	printf( "[ras_verify] rsa_pkcs1_verify ok\n" );
	
	rsa_free( &rsa );

	return( 0 );
}

//wwq add end


#if defined(POLARSSL_SELF_TEST)
#include "sha1.h"

static int myrand( void *rng_state )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    return( rand() );
}

/*
 * Checkup routine
 */
int rsa_self_test( int verbose )
{
    int len;
    rsa_context rsa;
    unsigned char sha1sum[20];
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];

    rsa_init( &rsa, RSA_PKCS_V15, 0 );

    rsa.len = KEY_LEN;
    mpi_read_string( &rsa.N , 16, RSA_N  );
    mpi_read_string( &rsa.E , 16, RSA_E  );
    mpi_read_string( &rsa.D , 16, RSA_D  );
    mpi_read_string( &rsa.P , 16, RSA_P  );
    mpi_read_string( &rsa.Q , 16, RSA_Q  );
    mpi_read_string( &rsa.DP, 16, RSA_DP );
    mpi_read_string( &rsa.DQ, 16, RSA_DQ );
    mpi_read_string( &rsa.QP, 16, RSA_QP );

    if( verbose != 0 )
        //printf( "  RSA key validation: " );

    if( rsa_check_pubkey(  &rsa ) != 0 ||
        rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            //printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        //printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( rsa_pkcs1_encrypt( &rsa, &myrand, NULL, RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            //printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        //printf( "passed\n  PKCS#1 decryption : " );

    if( rsa_pkcs1_decrypt( &rsa, RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
			   sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            //printf( "failed\n" );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            //printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        //printf( "passed\n  PKCS#1 data sign  : " );

    sha1( rsa_plaintext, PT_LEN, sha1sum );

    if( rsa_pkcs1_sign( &rsa, RSA_PRIVATE, SIG_RSA_SHA1, 20,
                        sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            //printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        //printf( "passed\n  PKCS#1 sig. verify: " );

    if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA1, 20,
                          sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            //printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        //printf( "passed\n\n" );

    rsa_free( &rsa );

    return( 0 );
}

#endif

#endif
