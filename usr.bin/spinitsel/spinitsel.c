#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>

int
main(void)
{
	int rc, s, n;
	fd_set rfd;

	s = socket(PF_INET6, SOCK_DGRAM, 0);
	
	while (1) {
		FD_ZERO(&rfd);
		FD_SET(s, &rfd);
		n = 1;
		
		rc = select(n, &rfd, NULL, NULL, NULL);
		if (rc < 0) {
			printf("select failed: %d\n", rc);
			sleep(10);
		}
	}

	/* NOT REACHED */
	return (0);
}
