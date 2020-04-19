//
//  RuntimeSymPatch.c
//  RuntimeSymPatch
//
//  
//  Copyright © 2020 Anonymouz4. All rights reserved.
//

#include "RuntimeSymPatch.h"

#ifndef KERNEL
	#include <stdlib.h>			// malloc, NULL
	#include <mach/mach.h>		// mach_task_self(), current_task()
	#include <mach/mach_vm.h>	// mach_vm_*
#else
	#include "KernelTools.h"
	#include <string.h>
#endif

#include <mach-o/loader.h>	// mach_header related
#include <mach-o/nlist.h>	// nlist_64

#pragma mark Private Header

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct nlist_64 nlist_t;
typedef struct section_64 section_t;

typedef struct {
	char*		name;
	uint8_t		n_type;		/* type flag, see <mach-o/nlist.h> */
    uint8_t		n_sect;		/* section number or NO_SECT */
    uint16_t	n_desc;		/* see <mach-o/stab.h> */
	void**		value_ptr;	/* points to the value of the symbol table entry */
} symbol_t;

static struct {
	bool			initialized;
	// Processing
	mach_header_t*	header;
	uint32_t		nsyms;
	nlist_t*		symbol_table;
	char*			str_table;
	uint32_t*		indirect_symtab;
	section_t**		la_symb_sections;
	uint32_t		la_symb_section_count;
	section_t**		nl_symb_sections;
	uint32_t		nl_symb_section_count;
	void*			linkedit_addr;
	// Final Output
	symbol_t*		symbols;
	uint32_t		symbols_count;
} symbols_info = {0};

#ifndef SEG_DATA_CONST
	#define SEG_DATA_CONST  "__DATA_CONST"
#endif
//Macros
#define valid_magic(magic) ((magic == MH_MAGIC_64 || magic == MH_CIGAM_64) ? true:false)
#define InitCheck() if (!symbols_info.initialized) {CLOG("Not initialized!");return 0;}

//Memory
	bool unprotectRegion(void* region_address);
	void* baseAddress(void);
//Mach-O Enum
	bool dumpMachO(void* baseAddress);
	bool dumpHeader(void* baseAddress);
	struct load_command* get_load_command(uint32_t cmd);
//Symbol Enum
	bool getSymbolInfos(void);
	bool getAllSymbols(void);
	bool getDirectSymbols(void);
	bool getIndirectSymbols(void);
	bool getIndirectSymbolsE(bool lazy);
//Symbol Patch
	void* getSymbolAddr(char* symbol_name);
	bool replaceSymbol(char* symbol_name, void* replacement_addr);
//Debug
	void printSymbolType(uint32_t type);
	char* symbolDesc(uint16_t desc);
	void printSymbol(char* str_table, nlist_t symbol);

#pragma mark -



#pragma mark - Initialization

static vm_map_t cur_task_map = 0;

bool InitRuntimeSymPatch() {
	
	#ifdef KERNEL
		if (_kernel_map) cur_task_map = kernel_map;
		void* base = (void*)kernel_text_base;
	#else
		cur_task_map = mach_task_self();
		void* base = baseAddress();
	#endif
	if (!cur_task_map) { CLOG("no task_map"); return false; }
	if (!base) { CLOG("no baseAddress"); return false; }
	
	bool success = false;
	
	success = dumpMachO(base);
	if (!success) { CLOG("dumpMachO failed"); return false; }
	
	#ifndef KERNEL
		//Make Symtab (__LINKEDIT region) writable for symbol patches
		success = unprotectRegion(symbols_info.linkedit_addr);
		if (!success) { CLOG("unprotectRegion failed"); return false; }
	#endif
	
	symbols_info.initialized = true;
	
	return true;
}

#pragma mark - Memory

#ifndef KERNEL
bool unprotectRegion(void* region_address) {
	vm_map_offset_t region_addr = (vm_map_offset_t)region_address;
    vm_map_size_t region_size = 0;
    uint32_t depth = 0;
    struct vm_region_submap_info_64 regionInfo;
	mach_msg_type_number_t regionInfoCount = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t kr = mach_vm_region_recurse(cur_task_map, &region_addr, &region_size, &depth, (vm_region_recurse_info_64_t)&regionInfo, &regionInfoCount);

	kr = mach_vm_protect(cur_task_map, region_addr, region_size, false, VM_PROT_DEFAULT | VM_PROT_COPY);
	return kr == KERN_SUCCESS;
}
void* baseAddress() {
	vm_map_offset_t vmoffset = 0; //_TEXT offset due to ASLR
    vm_map_size_t vmsize = 0;
    uint32_t depth = 0;
    struct vm_region_submap_info_64 info;
	mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
	mach_vm_region_recurse(cur_task_map, &vmoffset, &vmsize, &depth, (vm_region_recurse_info_64_t)&info, &info_count);
	return (void*)vmoffset;
}
#endif

#pragma mark - Mach-O Enum
bool dumpMachO(void* baseAddress) {
	
	bool success = false;
	
	success = dumpHeader(baseAddress);
	if (!success) { CLOG("dumpHeader failed"); return false; }
	
	success = getSymbolInfos();
	if (!success) { CLOG("getSymbolInfos failed"); return false; }
	
	success = getAllSymbols();
	if (!success) { CLOG("getAllSymbols failed"); return false; }
	
	return true;
}

bool dumpHeader(void* baseAddress) {
	uint32_t magic = *(uint32_t*)baseAddress;
	if (!valid_magic(magic)) return false;
	symbols_info.header = baseAddress;
	return true;
}

struct load_command* get_load_command(uint32_t cmd) {
    struct load_command* lc = (void*)symbols_info.header + sizeof(struct mach_header_64);
    if (cmd)
        for (uint i = 0; i < symbols_info.header->ncmds; i++) {
            if (lc->cmd == cmd) break;
            lc = (void*)lc + lc->cmdsize;
        }
    return lc;
}


#pragma mark - Symbol Enum

bool getSymbolInfos() {
	
	segment_command_t *cur_seg_cmd;
	struct symtab_command* symtab_cmd = NULL;
	struct dysymtab_command* dysymtab_cmd = NULL;

	void* cur = (void*)symbols_info.header + sizeof(mach_header_t);
	
	segment_command_t** lcs = malloc(symbols_info.header->ncmds*sizeof(segment_command_t*));
	bzero(lcs, symbols_info.header->ncmds*sizeof(segment_command_t*));
	
	for (uint i = 0; i < symbols_info.header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
		cur_seg_cmd = cur;
		if (cur_seg_cmd->cmd == LC_SYMTAB) symtab_cmd = (struct symtab_command*)cur_seg_cmd;
		else if (cur_seg_cmd->cmd == LC_DYSYMTAB) dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
		else if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
			lcs[i] = cur_seg_cmd;
			if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) symbols_info.linkedit_addr = (void*)symbols_info.header + cur_seg_cmd->fileoff;
			else if (strcmp(cur_seg_cmd->segname, SEG_DATA) == 0) symbols_info.la_symb_sections = malloc(sizeof(section_t*)*cur_seg_cmd->nsects);
			else if (strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) == 0) symbols_info.nl_symb_sections = malloc(sizeof(section_t*)*cur_seg_cmd->nsects);
			else continue;
            for (uint ii = 0; ii < cur_seg_cmd->nsects; ii++) {
				section_t *sect = cur + sizeof(segment_command_t) + (sizeof(section_t)*ii);
				if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
					symbols_info.la_symb_sections[symbols_info.la_symb_section_count] = sect;
					symbols_info.la_symb_section_count++;
				} else if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
					symbols_info.nl_symb_section_count++;
					symbols_info.nl_symb_sections[symbols_info.nl_symb_section_count-1] = sect;
				}
            }
        }
	}
	
	#ifdef KERNEL
		if (!symtab_cmd || !dysymtab_cmd) return false;
	#else
		if (!symtab_cmd || !dysymtab_cmd || !dysymtab_cmd->nindirectsyms) return false;
	#endif
	
	symbols_info.nsyms = symtab_cmd->nsyms;

	for (int i=0;i<symbols_info.header->ncmds;i++) {
		segment_command_t* seg = lcs[i];
		if (seg == NULL) continue;
		
		// Direct Symbols
			// Symbol Table
			if(seg->fileoff <= symtab_cmd->symoff && seg->fileoff + seg->filesize > symtab_cmd->symoff)
				symbols_info.symbol_table = (void*)(seg->vmaddr + symtab_cmd->symoff - seg->fileoff);
			// String Table
			if(seg->fileoff <= symtab_cmd->stroff && seg->fileoff + seg->filesize > symtab_cmd->stroff)
				symbols_info.str_table = (char*)(seg->vmaddr + symtab_cmd->stroff - seg->fileoff);
		//Indirect Symbols
		if(seg->fileoff <= dysymtab_cmd->indirectsymoff && seg->fileoff + seg->filesize > dysymtab_cmd->indirectsymoff)
			symbols_info.indirect_symtab = (void*)(seg->vmaddr + dysymtab_cmd->indirectsymoff - seg->fileoff);
	}
	
	#ifdef KERNEL
		free(lcs, symbols_info.header->ncmds*sizeof(segment_command_t*));
	#else
		free(lcs);
	#endif
	
	return symbols_info.symbol_table == NULL ? false:true;
}

bool getAllSymbols() {
	return getDirectSymbols() & getIndirectSymbols();
}
	
extern kern_return_t (*_mach_vm_read_overwrite)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,mach_vm_address_t data,mach_vm_size_t *outsize);
extern kern_return_t (*_mach_vm_read)(vm_map_t target_task,mach_vm_address_t address,mach_vm_size_t size,vm_offset_t *data,mach_msg_type_number_t *dataCnt);

bool getDirectSymbols() {
	
	nlist_t *symbol_table = symbols_info.symbol_table;
	symbols_info.symbols = malloc(sizeof(symbol_t)*symbols_info.nsyms);
	
	for (int i=0;i<symbols_info.nsyms;i++) {
		symbol_t symbol = {0};
		symbol.name = symbol_table[i].n_un.n_strx == 1 ? "<undefined>" : symbols_info.str_table + symbol_table[i].n_un.n_strx;
		symbol.n_type = symbol_table[i].n_type;
		symbol.n_sect = symbol_table[i].n_sect;
		symbol.n_desc = symbol_table[i].n_desc;
		symbol.value_ptr = (void**)&symbol_table[i].n_value;

		symbols_info.symbols[symbols_info.symbols_count] = symbol;
		symbols_info.symbols_count++;
		//printSymbol(info->str_table,symbol_table[i]);
	}
	
	return symbols_info.symbols_count > 0;
}

bool getIndirectSymbols() {
	return getIndirectSymbolsE(false) & getIndirectSymbolsE(true);
}
bool getIndirectSymbolsE(bool lazy) {
	
	section_t** sections = lazy ? symbols_info.la_symb_sections:symbols_info.nl_symb_sections;
	uint32_t section_count = lazy ? symbols_info.la_symb_section_count:symbols_info.nl_symb_section_count;
	
	//Enumrate over Sections
	for (uint i=0;i<section_count;i++) {
		section_t* section = sections[i];
		
		uint32_t *indirect_symbol_indices = symbols_info.indirect_symtab + section->reserved1;
		void **indirect_symbol_bindings = (void*)symbols_info.header + section->offset;
		
		uint nsymb = (uint)(section->size / sizeof(void*));
		
		for (uint ii = 0; ii < nsymb; ii++) {
			uint32_t symtab_index = indirect_symbol_indices[ii];
			
			if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL || symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
			
			symbol_t *undefSym = &symbols_info.symbols[symtab_index];
			undefSym->value_ptr = &indirect_symbol_bindings[ii];
		}
	}
	return true;
}



#pragma mark - Symbol Patch

void* getSymbolAddr(char* symbol_name) {
	InitCheck()
	for (uint i=0;i<symbols_info.symbols_count;i++)
		if (strcmp(symbols_info.symbols[i].name + 1, symbol_name) == 0) return *symbols_info.symbols[i].value_ptr;
	
	return NULL;
}

bool replaceSymbol(char* symbol_name, void* replacement_addr) {
	InitCheck()
	bool patched = false;
	for (uint i=0;i<symbols_info.symbols_count;i++)
		if (strcmp(symbols_info.symbols[i].name + 1, symbol_name) == 0) {
			if ((symbols_info.symbols[i].n_type & N_STAB) != 0) continue; // removing could have use to prevent hook detection
			
			#ifdef KERNEL
				paddr_t paddr = kernel_virtual_to_physical((kaddr_t)*symbols_info.symbols[i].value_ptr);
				if (paddr == 0) continue;
				bool success = kWrite64PHY(paddr, (uint64_t)replacement_addr);
				if (!success) continue;
			#else
				*symbols_info.symbols[i].value_ptr = replacement_addr;
			#endif
			
			CLOG("Patched Symbol!");
			printSymbolType(symbols_info.symbols[i].n_type);
			patched = true;
		}
	return patched;
}


#pragma mark - Debug

void printSymbolType(uint32_t type) {
	if ((type & N_STAB) != 0) CLOG("\tN_STAB");	/* if any of these bits set, a symbolic debugging entry */
	if ((type & N_PEXT) != 0) CLOG("\tN_PEXT");	/* private external symbol bit */
	if ((type & N_TYPE) != 0) CLOG("\tN_TYPE");	/* mask for the type bits */
	if ((type & N_EXT) != 0) CLOG("\tN_EXT");	/* external symbol bit, set for external symbols */
	if ((type & N_UNDF) != 0) CLOG("\tN_UNDF");	/* undefined, n_sect == NO_SECT */
	if ((type & N_ABS) != 0) CLOG("\tN_ABS");	/* absolute, n_sect == NO_SECT */
	if ((type & N_SECT) != 0) CLOG("\tN_SECT");	/* defined in section number n_sect */
	if ((type & N_PBUD) != 0) CLOG("\tN_PBUD");	/* prebound undefined (defined in a dylib) */
	if ((type & N_INDR) != 0) CLOG("\tN_INDR");	/* indirect */
}
char* symbolDesc(uint16_t desc) {
	char* desc_str = "-";
	switch (desc) {
		case REFERENCE_FLAG_UNDEFINED_NON_LAZY: desc_str = "UNDEFINED_NON_LAZY"; break;
		case REFERENCE_FLAG_UNDEFINED_LAZY: desc_str = "UNDEFINED_LAZY"; break;
		case REFERENCE_FLAG_DEFINED: desc_str = "DEFINED"; break;
		case REFERENCE_FLAG_PRIVATE_DEFINED: desc_str = "PRIVATE_DEFINED"; break;
		case REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: desc_str = "PRIVATE_UNDEFINED_NON_LAZY"; break;
		case REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: desc_str = "PRIVATE_UNDEFINED_LAZY"; break;
		default: break;
	}
	return desc_str;
}
void printSymbol(char* str_table, nlist_t symbol) {
	
	uint32_t strtab_offset = symbol.n_un.n_strx;
	
	char *csymbol_name = str_table + strtab_offset;
	bool symbol_name_longer_than_1 = csymbol_name[0] && csymbol_name[1];
	
	if (!symbol_name_longer_than_1) csymbol_name = "<undef>";

	CLOG("%s:	0x%llx		%s",csymbol_name,symbol.n_value,symbolDesc(symbol.n_desc));
	printSymbolType(symbol.n_type);
}
