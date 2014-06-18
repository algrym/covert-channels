/*
 * Covert Channel client/server
 *
 * $Id: util.c,v 1.1 2006/03/17 17:51:39 ajw Exp $
 *
 * A. J. Wright - <ajw@utk.edu>
 *
 */

#include <stdio.h>
#include <ctype.h>
#include "util.h"

/* convert an unsigned long to a string */
char *
ip2str (const unsigned long int addr)
{
  static char ret[IP2STR_BUFSIZE];

  unsigned char *i = (unsigned char *) &addr;
  sprintf (ret, "%i.%i.%i.%i", i[0], i[1], i[2], i[3]);

  return ret;
}

void
dumpRam (const unsigned char *aBuf, const size_t length)
{
  unsigned int Current = 0, Begin = 0, i;
  size_t start = 0;

  while (Current < length)
    {
      printf (" %.8lx  ", (unsigned int) Current + start);
      Begin = Current;

      for (i = 0; i < 8; i++)
	{
	  printf ("%.2hx ", aBuf[Current++]);
	  if (Current > length)
	    {
	      while (++i < 8)
		printf ("   ");
	      break;
	    }
	}

      if (Current <= length)
	{
	  printf ("- ");
	  for (i = 0; i < 8; i++)
	    {
	      printf ("%.2hx ", aBuf[Current++]);
	      if (Current > length)
		{
		  while (++i < 8)
		    printf ("   ");
		  break;
		}
	    }
	  printf ("   ");
	}
      else
	printf ("                             ");

      for (i = 0; i < 16; i++)
	{
	  if (isprint ((int) aBuf[Begin]))
	    printf ("%c", aBuf[Begin]);
	  else
	    printf ("_");
	  Begin++;
	  if (Begin > length)
	    {
	      printf ("\n");
	      return;
	    }
	}

      printf ("\n");
    }
}
