/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

extern "C" {
#include "config.h"
}

#include <stdio.h>
#include <iostream>

extern "C" {
int test_crc32(void);
int test_base64(void);
int test_stun(void);
int test_connectivity(void);
int test_thread(void);
int test_mux(void);
int test_notrickle(void);
int test_gathering(void);
int test_turn(void);
int test_conflict(void);
int test_bind(void);
int test_ufrag(void);
}

#ifndef NO_SERVER
int test_server(void);
#endif

int main(int argc, char **argv, char **envp) {
	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	if (argc != 3 && argc != 5 && argc != 6) {
		std::cerr << "Usage: TurnTester <turn-server-endpoint> <port> [<user> <pass>]\nFor shared-secret, first use the mTurnAuthGenerator to create a time-limited token.\n";
		return -1;
	}

	TurnServer = argv[1];
	if (argc > 2) {
		TurnPort = atoi(argv[2]);
		TurnUsername = argv[3];
		TurnPassword = argv[4];
	} else {
		TurnPort = 443;
		TurnUsername = "1704991274";
		TurnPassword = "RKss8KEHRtYynTBWv48hS63n";
	}

	std::cout << "*** Running TurnTester on the following TURN server: " << TurnServer << " ***" << std::endl;

	bool waitForAnyKey = argc != 6;

//	printf("\nRunning CRC32 implementation test...\n");
//	if (test_crc32()) {
//		fprintf(stderr, "CRC32 implementation test failed\n");
//		return -2;
//	}
//
//	printf("\nRunning base64 implementation test...\n");
//	if (test_base64()) {
//		fprintf(stderr, "base64 implementation test failed\n");
//		return -2;
//	}
//
//	printf("\nRunning STUN parsing implementation test...\n");
//	if (test_stun()) {
//		fprintf(stderr, "STUN parsing implementation test failed\n");
//		return -3;
//	}
//
//	printf("\nRunning candidates gathering test...\n");
//	if (test_gathering()) {
//		fprintf(stderr, "Candidates gathering test failed\n");
//		return -1;
//	}
//

	/*****************************************************
	*******************************************************
	*******************************************************
	* 
	* IMPORTANT!
	* 
	* Only enabled the tests that makes sense for testing
	* a remote TURN/STUN server. We are not interested
	* in testing libnice itself.
	* 
	* You need to provide a config.h file in the juice/src
	* folder with the following content:
	* -----------------------------------------------------
	* #define TurnServer    "turn.myvr.net"
	* #define TurnPort      443
	* #define TurnUsername  "VALID-USERNAME"
	* #define TurnPassword  "VALID-PASSWORD"
	* -----------------------------------------------------
	* 
	* Replace with proper values.
	* 
	*******************************************************
	*******************************************************
	******************************************************/

	printf("\nRunning connectivity test...\n");
	if (test_connectivity()) {
		fprintf(stderr, "Connectivity test failed\n");
		if (waitForAnyKey) { printf("\nPress any key to exit...\n"); getchar(); };
		return -1;
	}

	printf("\nRunning TURN connectivity test...\n");
	if (test_turn()) {
		fprintf(stderr, "TURN connectivity test failed\n");
		if (waitForAnyKey) { printf("\nPress any key to exit...\n"); getchar(); };
		return -1;
	}

	printf("\nRunning thread-mode connectivity test...\n");
	if (test_thread()) {
		fprintf(stderr, "Thread-mode connectivity test failed\n");
		if (waitForAnyKey) { printf("\nPress any key to exit...\n"); getchar(); };
		return -1;
	}

	printf("\nRunning mux-mode connectivity test...\n");
	if (test_mux()) {
		fprintf(stderr, "Mux-mode connectivity test failed\n");
		if (waitForAnyKey) { printf("\nPress any key to exit...\n"); getchar(); };
		return -1;
	}

	printf("\nRunning non-trickled connectivity test...\n");
	if (test_notrickle()) {
		fprintf(stderr, "Non-trickled connectivity test failed\n");
		if (waitForAnyKey) { printf("\nPress any key to exit...\n"); getchar(); };
		return -1;
	}

//	printf("\nRunning connectivity test with role conflict...\n");
//	if (test_conflict()) {
//		fprintf(stderr, "Connectivity test with role conflict failed\n");
//		return -1;
//	}
//
//	printf("\nRunning connectivity test with bind address...\n");
//	if (test_bind()) {
//		fprintf(stderr, "Connectivity test with bind address failed\n");
//		return -1;
//	}
//
//	printf("\nRunning ufrag test...\n");
//	if (test_ufrag()) {
//		fprintf(stderr, "Ufrag test failed\n");
//		return -1;
//	}0

//#ifndef NO_SERVER
//	printf("\nRunning server test...\n");
//	if (test_server()) {
//		fprintf(stderr, "Server test failed\n");
//		return -1;
//	}
//#endif

	if (waitForAnyKey) { printf("\nPress any key to exit...\n"); getchar(); };

	return 0;
}

