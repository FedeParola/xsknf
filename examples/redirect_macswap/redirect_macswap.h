void inline swap_mac_addresses(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

/*
 * I know this is stupid but it's the only way to prevent the compiler form
 * removing both macswaps
 */
void inline swap_mac_addresses_v2(void *data)
{
    unsigned char *macs = data;
	unsigned char tmp;

    for (int i = 0; i < 6; i++) {
        tmp = macs[i];
        macs[i] = macs[6 + i];
        macs[6 + i] = tmp;
    }
}
