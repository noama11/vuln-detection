static void pdf_parseobj(struct pdf_struct *pdf, struct pdf_obj *obj)
{
    /* enough to hold common pdf names, we don't need all the names */
    char pdfname[64];
    const char *q2, *q3;
    const char *q = obj->start + pdf->map;
    const char *dict, *start;
    off_t dict_length;
    off_t bytesleft = obj_size(pdf, obj, 1);
    unsigned i, filters=0;
    enum objstate objstate = STATE_NONE;

    if (bytesleft < 0)
	return;
    start = q;
    /* find start of dictionary */
    do {
	q2 = pdf_nextobject(q, bytesleft);
	bytesleft -= q2 -q;
	if (!q2 || bytesleft < 0) {
	    return;
	}
	q3 = memchr(q-1, '<', q2-q+1);
	q2++;
	bytesleft--;
	q = q2;
    } while (!q3 || q3[1] != '<');
    dict = q3+2;
    q = dict;
    bytesleft = obj_size(pdf, obj, 1) - (q - start);
    /* find end of dictionary */
    do {
	q2 = pdf_nextobject(q, bytesleft);
	bytesleft -= q2 -q;
	if (!q2 || bytesleft < 0) {
	    return;
	}
	q3 = memchr(q-1, '>', q2-q+1);
	q2++;
	bytesleft--;
	q = q2;
    } while (!q3 || q3[1] != '>');
    obj->flags |= 1 << OBJ_DICT;
    dict_length = q3 - dict;

    /*  process pdf names */
    for (q = dict;dict_length > 0;) {
	int escapes = 0;
	q2 = memchr(q, '/', dict_length);
	if (!q2)
	    break;
	dict_length -= q2 - q;
	q = q2;
	/* normalize PDF names */
	for (i = 0;dict_length > 0 && (i < sizeof(pdfname)-1); i++) {
	    q++;
	    dict_length--;
	    if (*q == '#') {
		if (cli_hex2str_to(q+1, pdfname+i, 2) == -1)
		    break;
		q += 2;
		dict_length -= 2;
		escapes = 1;
		continue;
	    }
	    if (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n' ||
		*q == '/' || *q == '>' || *q == ']' || *q == '[' || *q == '<'
		|| *q == '(')
		break;
	    pdfname[i] = *q;
	}
	pdfname[i] = '\0';

	handle_pdfname(pdf, obj, pdfname, escapes, &objstate);
	if (objstate == STATE_LINEARIZED) {
	    long trailer_end, trailer;
	    pdfobj_flag(pdf, obj, LINEARIZED_PDF);
	    objstate = STATE_NONE;
	    trailer_end = pdf_readint(q, dict_length, "/H");
	    if (trailer_end > 0 && trailer_end < pdf->size) {
		trailer = trailer_end - 1024;
		if (trailer < 0) trailer = 0;
		q2 = pdf->map + trailer;
		cli_dbgmsg("cli_pdf: looking for trailer in linearized pdf: %ld - %ld\n", trailer, trailer_end);
		pdf_parse_trailer(pdf, q2, trailer_end - trailer);
		if (pdf->fileID)
		    cli_dbgmsg("cli_pdf: found fileID\n");
	    }
	}
	if (objstate == STATE_LAUNCHACTION)
	    pdfobj_flag(pdf, obj, HAS_LAUNCHACTION);
	if (dict_length > 0 && (objstate == STATE_JAVASCRIPT ||
	    objstate == STATE_OPENACTION)) {
	    if (objstate == STATE_OPENACTION)
		pdfobj_flag(pdf, obj, HAS_OPENACTION);
	    q2 = pdf_nextobject(q, dict_length);
	    if (q2 && isdigit(*q2)) {
		uint32_t objid = atoi(q2) << 8;
		while (isdigit(*q2)) q2++;
		q2 = pdf_nextobject(q2, dict_length);
		if (q2 && isdigit(*q2)) {
		    objid |= atoi(q2) & 0xff;
		    q2 = pdf_nextobject(q2, dict_length);
		    if (q2 && *q2 == 'R') {
			struct pdf_obj *obj2;
			cli_dbgmsg("cli_pdf: found %s stored in indirect object %u %u\n",
				   pdfname,
				   objid >> 8, objid&0xff);
			obj2 = find_obj(pdf, obj, objid);
			if (obj2) {
			    enum pdf_objflags flag = objstate == STATE_JAVASCRIPT ?
				OBJ_JAVASCRIPT : OBJ_OPENACTION;
			    obj2->flags |= 1 << flag;
			    obj->flags &= ~(1 << flag);
			} else {
			    pdfobj_flag(pdf, obj, BAD_INDOBJ);
			}
		    }
		}
	    }
	    objstate = STATE_NONE;
	}
    }
    for (i=0;i<sizeof(pdfname_actions)/sizeof(pdfname_actions[0]);i++) {
	const struct pdfname_action *act = &pdfname_actions[i];
	if ((obj->flags & (1 << act->set_objflag)) &&
	    act->from_state == STATE_FILTER &&
	    act->to_state == STATE_FILTER &&
	    act->set_objflag != OBJ_FILTER_CRYPT &&
	    act->set_objflag != OBJ_FILTER_STANDARD) {
	    filters++;
	}
    }
    if (filters > 2) { /* more than 2 non-crypt filters */
	pdfobj_flag(pdf, obj, MANY_FILTERS);
    }
    if (obj->flags & ((1 << OBJ_SIGNED) | KNOWN_FILTERS))
	obj->flags &= ~(1 << OBJ_FILTER_UNKNOWN);
    if (obj->flags & (1 << OBJ_FILTER_UNKNOWN))
	pdfobj_flag(pdf, obj, UNKNOWN_FILTER);
    cli_dbgmsg("cli_pdf: %u %u obj flags: %02x\n", obj->id>>8, obj->id&0xff, obj->flags);
}