BGD_DECLARE(void) gdImageXbmCtx(gdImagePtr image, char* file_name, int fg, gdIOCtx * out)
{
	int x, y, c, b, sx, sy, p;
	char *name, *f;
	size_t i, l;

	name = file_name;
	if ((f = strrchr(name, '/')) != NULL) name = f+1;
	if ((f = strrchr(name, '\\')) != NULL) name = f+1;
	name = strdup(name);
	if ((f = strrchr(name, '.')) != NULL && !strcasecmp(f, ".XBM")) *f = '\0';
	if ((l = strlen(name)) == 0) {
		free(name);
		name = strdup("image");
	} else {
		for (i=0; i<l; i++) {
			/* only in C-locale isalnum() would work */
			if (!isupper(name[i]) && !islower(name[i]) && !isdigit(name[i])) {
				name[i] = '_';
			}
		}
	}

	gdCtxPrintf(out, "#define %s_width %d\n", name, gdImageSX(image));
	gdCtxPrintf(out, "#define %s_height %d\n", name, gdImageSY(image));
	gdCtxPrintf(out, "static unsigned char %s_bits[] = {\n  ", name);

	free(name);

	b = 1;
	p = 0;
	c = 0;
	sx = gdImageSX(image);
	sy = gdImageSY(image);
	for (y = 0; y < sy; y++) {
		for (x = 0; x < sx; x++) {
			if (gdImageGetPixel(image, x, y) == fg) {
				c |= b;
			}
			if ((b == 128) || (x == sx && y == sy)) {
				b = 1;
				if (p) {
					gdCtxPrintf(out, ", ");
					if (!(p%12)) {
						gdCtxPrintf(out, "\n  ");
						p = 12;
					}
				}
				p++;
				gdCtxPrintf(out, "0x%02X", c);
				c = 0;
			} else {
				b <<= 1;
			}
		}
	}
	gdCtxPrintf(out, "};\n");
}