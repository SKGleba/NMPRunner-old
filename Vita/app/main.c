/*
 * Simple kplugin loader by xerpi
 */

#include <stdio.h>
#include <taihen.h>
#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include "debugScreen.h"

#define MOD_PATH "ux0:app/SKGNMPRUN/kplugin.skprx"
	
#define printf(...) psvDebugScreenPrintf(__VA_ARGS__)

void wait_key_press()
{
	SceCtrlData pad;

	printf("Press CROSS to run the payload.\n");

	while (1) {
		sceCtrlPeekBufferPositive(0, &pad, 1);
		if (pad.buttons & SCE_CTRL_CROSS)
			break;
		sceKernelDelayThread(200 * 1000);
	}
}

int main(int argc, char *argv[])
{
	int ret;
	SceUID mod_id;
	psvDebugScreenInit();
	printf("NMPRunner v1.0\n");
	wait_key_press();
	printf("\nRunning the payload...");
	tai_module_args_t argg;
	argg.size = sizeof(argg);
	argg.pid = KERNEL_PID;
	argg.args = 0;
	argg.argp = NULL;
	argg.flags = 0;
	mod_id = taiLoadStartKernelModuleForUser(MOD_PATH, &argg);
	if (mod_id > 0) {
		printf("\nok!, exiting in 5s\n");
		printf("you can check the log for more info\n");
		sceKernelDelayThread(5 * 1000 * 1000);
		taiStopUnloadKernelModuleForUser(mod_id, &argg, NULL, NULL);
		sceKernelExitProcess(0);
	} else {
		printf("\nerr! 0x%X\nexiting in 5s\n", mod_id);
		sceKernelDelayThread(5 * 1000 * 1000);
	}
	return 0;
}
