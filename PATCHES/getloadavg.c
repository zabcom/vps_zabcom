#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argvp[])
{
	double loadavg[3];
	int rc, nelem = 3;

	rc = getloadavg(loadavg, nelem);
	printf("rc %d %lf %lf %lf %d\n",
	    rc, loadavg[0], loadavg[1], loadavg[2], nelem);

	return (0);
}
