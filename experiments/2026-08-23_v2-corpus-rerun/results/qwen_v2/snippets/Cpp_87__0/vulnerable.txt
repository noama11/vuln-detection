static void pdfobj_flag(struct pdf_struct *pdf, struct pdf_obj *obj, enum pdf_flag flag)
{
    const char *s= "";
    pdf->flags |= 1 << flag;
    if (!cli_debug_flag)
	return;
    switch (flag) {
	case UNTERMINATED_OBJ_DICT:
	    s = "dictionary not terminated";
	    break;
	case ESCAPED_COMMON_PDFNAME:
	    /* like /JavaScript */
	    s = "escaped common pdfname";
	    break;
	case BAD_STREAM_FILTERS:
	    s = "duplicate stream filters";
	    break;
	case BAD_PDF_VERSION:
	    s = "bad pdf version";
	    break;
	case BAD_PDF_HEADERPOS:
	    s = "bad pdf header position";
	    break;
	case BAD_PDF_TRAILER:
	    s = "bad pdf trailer";
	    break;
	case BAD_PDF_TOOMANYOBJS:
	    s = "too many pdf objs";
	    break;
	case BAD_FLATE:
	    s = "bad deflate stream";
	    break;
	case BAD_FLATESTART:
	    s = "bad deflate stream start";
	    break;
	case BAD_STREAMSTART:
	    s = "bad stream start";
	    break;
	case UNKNOWN_FILTER:
	    s = "unknown filter used";
	    break;
	case BAD_ASCIIDECODE:
	    s = "bad ASCII decode";
	    break;
	case HEX_JAVASCRIPT:
	    s = "hex javascript";
	    break;
	case BAD_INDOBJ:
	    s = "referencing nonexistent obj";
	    break;
	case HAS_OPENACTION:
	    s = "has /OpenAction";
	    break;
	case HAS_LAUNCHACTION:
	    s = "has /LaunchAction";
	    break;
	case BAD_STREAMLEN:
	    s = "bad /Length, too small";
	    break;
	case ENCRYPTED_PDF:
	    s = "PDF is encrypted";
	    break;
	case LINEARIZED_PDF:
	    s = "linearized PDF";
	    break;
	case MANY_FILTERS:
	    s = "more than 2 filters per obj";
	    break;
    }
    cli_dbgmsg("cli_pdf: %s flagged in object %u %u\n", s, obj->id>>8, obj->id&0xff);
}