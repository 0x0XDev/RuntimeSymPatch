//
//  example.c
//  RuntimeSymPatch
//
//
//  Copyright © 2020 Anonymouz4. All rights reserved.
//

#include "RuntimeSymPatch.h"

#include <stdio.h>		//printf
#include <string.h>		//strlen


static size_t (*orig_strlen)(const char *__s);
size_t my_strlen(const char *__s) {
	return 0xff;
}

int main(int argc, const char * argv[]) {

	bool success = InitRuntimeSymPatch();
	if (!success) return 5;
	
	char* example = "example";
	printf("normal:		%lu\n",strlen(example));		// returns 7
	
	orig_strlen = getSymbolAddr("strlen");
	replaceSymbol("strlen", &my_strlen);
	
	printf("patched:	%lu\n",strlen(example));		// returns 0xff
	printf("original:	%lu\n",orig_strlen(example));	// returns 7
	
	return 0;
}

