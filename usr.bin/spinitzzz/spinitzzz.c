#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	unsigned int dt;

	dt = 3600;
	while (1) {
		dt = sleep(dt);
		if (dt == 0)
			dt = 3600;
		else
			printf("Time left: %u\n", dt);
	}

	/* NOT REACHED */
	return (0);
}
