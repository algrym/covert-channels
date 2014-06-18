/*
 * Covert Channel client/server
 *
 * $Id: util.h,v 1.2 2006/04/10 18:25:50 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#ifndef __UTIL_H
#define __UTIL_H

/* maximum size of an IP address, in text form:
   - four 3-char strings, one for each octet
   - three periods
   - one null
 */
#define IP2STR_BUFSIZE ((4 * 3 + 3 + 1) * sizeof (char))	/* 123.567.901.345(null) */

char *ip2str (const unsigned long int addr);
void dumpRam (const unsigned char *aBuf, const size_t length);

#endif /* __UTIL_H */
