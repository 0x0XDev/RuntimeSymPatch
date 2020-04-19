//
//  RuntimeSymPatch.h
//  RuntimeSymPatch
//
//
//  Copyright © 2020 Anonymouz4. All rights reserved.
//

#ifndef RuntimeSymPatch_h
#define RuntimeSymPatch_h

#include <stdbool.h>		// bool
#include <mach/vm_types.h>	// vm_map_t

// Note: Must be run once first!
bool InitRuntimeSymPatch(void);

// Note: Symbol Name may not contain leading '_'
void* getSymbolAddr(char* symbol_name);
bool replaceSymbol(char* symbol_name, void* replacement_addr);


//Set Preferred Logger
#ifdef KERNEL
#include "KLogger.h"
#define CLOG KLog
#else
#include <stdio.h>		// printf
#define CLOG(str, args...) \
do { \
	printf(str "\n", ##args); \
} while(0)
#endif

#endif /* RuntimeSymPatch_h */
