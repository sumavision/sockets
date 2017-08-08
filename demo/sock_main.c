#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>


#include "app_udp.h"



int main(int argc, char *argv[])
{
	udp_sock_start(90);
	
	return 0;
}