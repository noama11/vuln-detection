static void check_user_password(struct pdf_struct *pdf, int R, const char *O,
				const char *U, int32_t P, int EM,
				unsigned length, unsigned oulen)
{
    unsigned i;
    uint8_t result[16];
    char data[32];
    cli_md5_ctx md5;
    struct arc4_state arc4;
    unsigned password_empty = 0;

    dbg_printhex("U: ", U, 32);
    dbg_printhex("O: ", O, 32);
    if (R == 5) {
	uint8_t result2[32];
	SHA256_CTX sha256;
	/* supplement to ISO3200, 3.5.2 Algorithm 3.11 */
	sha256_init(&sha256);
	/* user validation salt */
	sha256_update(&sha256, U+32, 8);
	sha256_final(&sha256, result2);
	dbg_printhex("Computed U", result2, 32);
	if (!memcmp(result2, U, 32)) {
	    password_empty = 1;
	    /* Algorithm 3.2a could be used to recover encryption key */
	}
    } else {
	/* 7.6.3.3 Algorithm 2 */
	cli_md5_init(&md5);
	/* empty password, password == padding */
	cli_md5_update(&md5, key_padding, 32);
	cli_md5_update(&md5, O, 32);
	P = le32_to_host(P);
	cli_md5_update(&md5, &P, 4);
	cli_md5_update(&md5, pdf->fileID, pdf->fileIDlen);
	if (R >= 4 && !EM) {
	    uint32_t v = 0xFFFFFFFF;
	    cli_md5_update(&md5, &v, 4);
	}
	cli_md5_final(result, &md5);
	if (R >= 3) {
	    if (length > 128)
		length = 128;
	    for (i=0;i<50;i++) {
		cli_md5_init(&md5);
		cli_md5_update(&md5, result, length/8);
		cli_md5_final(result, &md5);
	    }
	}
	if (R == 2)
	    length = 40;
	pdf->keylen = length / 8;
	pdf->key = cli_malloc(pdf->keylen);
	if (!pdf->key)
	    return;
	memcpy(pdf->key, result, pdf->keylen);
	dbg_printhex("md5", result, 16);
	dbg_printhex("Candidate encryption key", pdf->key, pdf->keylen);

	/* 7.6.3.3 Algorithm 6 */
	if (R == 2) {
	    /* 7.6.3.3 Algorithm 4 */
	    memcpy(data, key_padding, 32);
	    arc4_init(&arc4, pdf->key, pdf->keylen);
	    arc4_apply(&arc4, data, 32);
	    dbg_printhex("computed U (R2)", data, 32);
	    if (!memcmp(data, U, 32))
		password_empty = 1;
	} else if (R >= 3) {
	    unsigned len = pdf->keylen;
	    /* 7.6.3.3 Algorithm 5 */
	    cli_md5_init(&md5);
	    cli_md5_update(&md5, key_padding, 32);
	    cli_md5_update(&md5, pdf->fileID, pdf->fileIDlen);
	    cli_md5_final(result, &md5);
	    memcpy(data, pdf->key, len);
	    arc4_init(&arc4, data, len);
	    arc4_apply(&arc4, result, 16);
	    for (i=1;i<=19;i++) {
		unsigned j;
		for (j=0;j<len;j++)
		    data[j] = pdf->key[j] ^ i;
		arc4_init(&arc4, data, len);
		arc4_apply(&arc4, result, 16);
	    }
	    dbg_printhex("fileID", pdf->fileID, pdf->fileIDlen);
	    dbg_printhex("computed U (R>=3)", result, 16);
	    if (!memcmp(result, U, 16))
		password_empty = 1;
	} else {
	    cli_dbgmsg("cli_pdf: invalid revision %d\n", R);
	}
    }
    if (password_empty) {
	cli_dbgmsg("cli_pdf: user password is empty\n");
	/* The key we computed above is the key used to encrypt the streams.
	 * We could decrypt it now if we wanted to */
	pdf->flags |= 1 << DECRYPTABLE_PDF;
    } else {
	cli_dbgmsg("cli_pdf: user/owner password would be required for decryption\n");
	/* the key is not valid, we would need the user or the owner password to
	 * decrypt */
    }
}