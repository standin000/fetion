#include "internal.h"

#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "dnsquery.h"
#include "debug.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"
#include "network.h"
#include "xmlnode.h"
#include "request.h"
#include "imgstore.h"
#include "sslconn.h"

#include "sipmsg.h"
#include "dnssrv.h"
#include "ntlm.h"

#include "sipmsg.h"
#include "f_util.h"
#include <openssl/rsa.h>
#include <openssl/sha.h>

extern gint g_callid;

gchar *gencnonce(void)
{
	return g_strdup_printf("%04X%04X%04X%04X%04X%04X%04X%04X",
			       rand() & 0xFFFF, rand() & 0xFFFF,
			       rand() & 0xFFFF, rand() & 0xFFFF,
			       rand() & 0xFFFF, rand() & 0xFFFF,
			       rand() & 0xFFFF, rand() & 0xFFFF);
}

gchar *gencallid(void)
{
	return g_strdup_printf("%d", ++g_callid);
}

gchar *get_token(const gchar * str, const gchar * start, const gchar * end)
{
	const char *c, *c2;

	if ((c = strstr(str, start)) == NULL)
		return NULL;

	c += strlen(start);

	if (end != NULL) {
		if ((c2 = strstr(c, end)) == NULL)
			return NULL;

		return g_strndup(c, c2 - c);
	} else {
		/* This has to be changed */
		return g_strdup(c);
	}

}

gchar *fetion_cipher_digest_calculate_response(const gchar * sid,
					       const gchar * domain,
					       const gchar * password,
					       const gchar * nonce,
					       const gchar * cnonce)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	gchar *hash1;		/* We only support MD5. */
	gchar *hash2;		/* We only support MD5. */
	gchar temp[33];
	gchar *response;	/* We only support MD5. */
	guchar digest[16];

	g_return_val_if_fail(sid != NULL, NULL);
	g_return_val_if_fail(domain != NULL, NULL);
	g_return_val_if_fail(password != NULL, NULL);
	g_return_val_if_fail(nonce != NULL, NULL);
	g_return_val_if_fail(cnonce != NULL, NULL);

	cipher = purple_ciphers_find_cipher("md5");
	g_return_val_if_fail(cipher != NULL, NULL);

	context = purple_cipher_context_new(cipher, NULL);

	purple_cipher_context_append(context, (guchar *) sid, strlen(sid));
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) domain,
				     strlen(domain));
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) password,
				     strlen(password));

	purple_cipher_context_digest(context, sizeof(digest), digest, NULL);
	purple_cipher_context_destroy(context);

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, digest, 16);
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) nonce, strlen(nonce));
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) cnonce,
				     strlen(cnonce));
	purple_cipher_context_digest_to_str(context, sizeof(temp), temp, NULL);
	purple_cipher_context_destroy(context);
	hash1 = g_ascii_strup(temp, 32);

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar *) "REGISTER", 8);
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) sid, strlen(sid));
	purple_cipher_context_digest_to_str(context, sizeof(temp), temp, NULL);

	hash2 = g_ascii_strup(temp, 32);

	purple_cipher_context_destroy(context);
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar *) hash1, strlen(hash1));
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) nonce, strlen(nonce));
	purple_cipher_context_append(context, (guchar *) ":", 1);
	purple_cipher_context_append(context, (guchar *) hash2, strlen(hash2));
	purple_cipher_context_digest_to_str(context, sizeof(temp), temp, NULL);
	purple_cipher_context_destroy(context);

	response = g_ascii_strup(temp, 32);
	return g_strdup(response);
}

gboolean IsCMccNo(gchar * name)
{
	gint mobileNo;
	gint head;
	gchar *szMobile;
	szMobile = g_strdup(name);
	szMobile[7] = '\0';
	mobileNo = atoi(szMobile);

	head = mobileNo / 10000;
	purple_debug_info("fetion:", "IsCMccNo:[%d]\n", mobileNo);
	g_free(szMobile);
	if ((mobileNo <= 1300000) || (mobileNo >= 1600000)) {
		return FALSE;
	}
	if (((head < 134) || (head > 139))
	    && (((head != 159) && (head != 158)) && (head != 157))) {
		return (head == 150);
	}
	return TRUE;

}

gboolean IsUnicomNo(gchar * name)
{
	gint mobileNo;
	gint head;
	gchar *szMobile;
	szMobile = g_strdup(name);
	szMobile[7] = '\0';
	mobileNo = atoi(szMobile);
	head = mobileNo / 10000;
	g_free(szMobile);
	if ((mobileNo <= 1300000) || (mobileNo >= 1600000)) {
		return FALSE;
	}
	if (((head >= 130) && (head <= 133)) || head == 153) {
		return TRUE;
	}

	return FALSE;

}

gchar *auth_header(struct fetion_account_data * sip,
		   struct sip_auth * auth, const gchar * method,
		   const gchar * target)
{
	gchar *ret;
	ret =
	    g_strdup_printf("Digest response=\"%s\",cnonce=\"%s\"",
			    auth->digest_session_key, auth->cnonce);
	return ret;
}

gchar *parse_attribute(const gchar * attrname, const gchar * source)
{
	const char *tmp;
	char *retval = NULL;
	int len = strlen(attrname);
	tmp = strstr(source, attrname);

	if (tmp)
		retval = g_strdup(tmp + len);

	return retval;
}

void
fill_auth(struct fetion_account_data *sip, const gchar * hdr,
	  struct sip_auth *auth)
{
	gchar *tmp;
        char *key, *aeskey;

	if (!hdr) {
		purple_debug_error("fetion", "fill_auth: hdr==NULL\n");
		return;
	}

	auth->type = 1;
	auth->cnonce = gencnonce();
	auth->domain = g_strdup("fetion.com.cn");
	if ((tmp = parse_attribute("nonce=\"", hdr)))
		auth->nonce = g_ascii_strup(tmp, 32);

        key = g_strndup(strstr(hdr,"key=\"")+5, 262);
        
        /* if ((tmp = parse_attribute("key=\"", hdr))) */
	/* 	key = g_ascii_strup(tmp, 262); */

	purple_debug(PURPLE_DEBUG_MISC, "fetion", "nonce: %s domain: %s\nkey: %s!\nuserid:%s",
		     auth->nonce ? auth->nonce : "(null)",
		     auth->domain ? auth->domain : "(null)",
                     key, sip->password);

        aeskey = generate_aes_key();

	if (auth->domain)
                /* Plato Wu,2010/09/29: SIP/C-4.0 use RSA algorithm to calculate response */
		/* auth->digest_session_key = */
		/*     fetion_cipher_digest_calculate_response(sip->username, */
		/* 					    auth->domain, */
		/* 					    sip->password, */
		/* 					    auth->nonce, */
		/* 					    auth->cnonce); */
		auth->digest_session_key =
                        generate_response(auth->nonce, sip->uid, sip->password, key, aeskey);
        free(key);
        free(aeskey);
}

gchar *parse_from(const gchar * hdr)
{
	gchar *from;
	const gchar *tmp, *tmp2 = hdr;

	if (!hdr)
		return NULL;
	purple_debug_info("fetion", "parsing address out of %s\n", hdr);
	tmp = strchr(hdr, '<');

	/* i hate the different SIP UA behaviours... */
	if (tmp) {		/* sip address in <...> */
		tmp2 = tmp + 1;
		tmp = strchr(tmp2, '>');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			purple_debug_info("fetion",
					  "found < without > in From\n");
			return NULL;
		}
	} else {
		tmp = strchr(tmp2, ';');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			from = g_strdup(tmp2);
		}
	}
	purple_debug_info("fetion", "got %s\n", from);
	return from;
}
extern char* hash_password_v4(const char* userid , const char* password);
unsigned char* strtohex(const char* in , int* len) 
{
	unsigned char* out = (unsigned char*)malloc(strlen(in)/2 );
	int i = 0 , j = 0 , k = 0 ,length = 0;
	char tmp[3] = { 0 };
	memset(out , 0 , strlen(in) / 2);
	while(i < (int)strlen(in))
	{
		tmp[k++] = in[i++];
		tmp[k] = '\0';
		if(k == 2)
		{
			out[j++] = (unsigned char)strtol(tmp , (char**)NULL , 16);
			k = 0;
			length ++;
		}
	}
	if(len != NULL )
		*len = length;
	return out;
}

char* hextostr(const unsigned char* in , int len) 
{
	char* res = (char*)malloc(len * 2 + 1);
	int i = 0;
	memset(res , 0 , len * 2 + 1);
	while(i < len)
	{
		sprintf(res + i * 2 , "%02x" , in[i]);
		i ++;
	};
	i = 0;
	while(i < (int)strlen(res))
	{
		res[i] = toupper(res[i]);
		i ++;
	};
        /* Plato Wu,2010/09/24: why dont's free it. */
        free(in);
        
	return res;
}

char* generate_aes_key()
{
	char* key = (char*)malloc(65);
	memset( key , 0 , 65 );
	sprintf( key , "%04x%04x%04x%04x%04x%04x%04x"
			"%04x%04x%04x%04x%04x%04x%04x%04x%04x" , 
			rand() & 0xFFFF , rand() & 0xFFFF , 
			rand() & 0xFFFF , rand() & 0xFFFF , 
			rand() & 0xFFFF , rand() & 0xFFFF , 
			rand() & 0xFFFF , rand() & 0xFFFF , 
			rand() & 0xFFFF , rand() & 0xFFFF , 
			rand() & 0xFFFF , rand() & 0xFFFF ,
			rand() & 0xFFFF , rand() & 0xFFFF,
			rand() & 0xFFFF , rand() & 0xFFFF );
	return key;
}
/* Plato Wu,2010/09/29: Copy from Openfetion for SIP-C/4.0 */
char* generate_response(const char* nouce , const char* userid 
		, const char* password , const char* publickey , const char* key)
{

	char* psdhex = hash_password_v4(userid , password);
	char modulus[257];
	char exponent[7];
	int ret, flen;
	BIGNUM *bnn, *bne;
	unsigned char *out;
	unsigned char *nonce , *aeskey , *psd , *res;
	int nonce_len , aeskey_len , psd_len;
	RSA *r = RSA_new();

	key = NULL;

	memset(modulus, 0, sizeof(modulus));
	memset(exponent, 0, sizeof(exponent));

	memcpy(modulus , publickey , 256);
	memcpy(exponent , publickey + 256 , 6);
	nonce = (unsigned char*)malloc(strlen(nouce) + 1);
	memset(nonce , 0 , strlen(nouce) + 1);
	memcpy(nonce , (unsigned char*)nouce , strlen(nouce));
	nonce_len = strlen(nouce);
	psd = strtohex(psdhex , &psd_len);
        free(psdhex);
        psdhex = generate_aes_key();
        
	//aeskey = strtohex(generate_aes_key() , &aeskey_len);
              aeskey = strtohex(psdhex, &aeskey_len);
//        aeskey = strtohex(psdhex, &aeskey_len);

//        psdhex = g_strdup("d4a1c83edde91a70f0878ddcbd3df5218641f8741d82c40e861124549eb4769b");
                           
//        aeskey = strtohex(psdhex, &aeskey_len);
        
    printf("nonce is %s, userid is %s, password is %s, publickey is %s, key is %s, aeskey is %s!!!",
           nonce, userid, password, publickey, key, psdhex);
    free(psdhex);
    

	res = (unsigned char*)malloc(nonce_len + aeskey_len + psd_len + 1);
	memset(res , 0 , nonce_len + aeskey_len + psd_len + 1);
	memcpy(res , nonce , nonce_len);
	memcpy(res + nonce_len , psd , psd_len );
	memcpy(res + nonce_len + psd_len , aeskey , aeskey_len);

	bnn = BN_new();
	bne = BN_new();
	BN_hex2bn(&bnn, modulus);
	BN_hex2bn(&bne, exponent);
	r->n = bnn;	r->e = bne;	r->d = NULL;
	RSA_print_fp(stdout, r, 5);
	flen = RSA_size(r);
	out =  (unsigned char*)malloc(flen);
	memset(out , 0 , flen);
	ret = RSA_public_encrypt(nonce_len + aeskey_len + psd_len, res , out, r, RSA_PKCS1_PADDING);

	if (ret < 0)
	{
		return NULL;
	}
	RSA_free(r);
	free(res); 
	free(aeskey);
	free(psd);
	free(nonce);
	return hextostr(out , ret);
}
