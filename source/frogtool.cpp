#include <3ds.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include "frogtool.h"

Result import_tad(u64 tid, u8 op, u8 *workbuf, const char *ext) {
	Handle handle;
	Result res;
	FS_Path filePath;
	FS_Path archPath = { PATH_EMPTY, 1, (u8*)"" };
	char fpath[64]={0};
	uint16_t filepath16[256];
	ssize_t units=0;
	u32 len=255;
	
	memset(fpath, 0, 64);
	sprintf(fpath,"sdmc:/%08lX%s",(u32)tid, ext);
	if(access(fpath, F_OK ) == -1 ) {
		printf("%s missing on SD\n\n",fpath);
		return 1;
	
	}
	memset(filepath16, 0, sizeof(filepath16));
	units = utf8_to_utf16(filepath16, (u8*)(fpath+5), len);
	
	filePath.type = PATH_UTF16;
	filePath.size = (units+1)*sizeof(uint16_t);
	filePath.data = (const u8*)filepath16;
	
	printf("import:%d %s\n", op, fpath);
	res = FSUSER_OpenFileDirectly(&handle, ARCHIVE_SDMC, archPath, filePath, FS_OPEN_READ, 0);
	printf("fsopen: %08X\n",(int)res);
	printf("importing dsiware...\n");
	res = AM_ImportTwlBackup(handle, op, workbuf, 0x20000);
	printf("twl import: %08X %s\n\n",(int)res, res ? "FAILED!" : "SUCCESS!");
	FSFILE_Close(handle);
	
	return res;
}

Result export_tad(u64 tid, u8 op, u8 *workbuf, const char *ext) {
	Result res;
	char fpath[256]={0};
	memset(fpath, 0, 128);
	sprintf(fpath,"sdmc:/%08lX%s",(u32)tid, ext);
	if(access(fpath, F_OK ) != -1 ) {
		printf("DS dlp already exists on SD\n\n");
		return 1;
	}
	printf("exporting:%d %016llX to\n%s...\n", op, tid, fpath);
	res = AM_ExportTwlBackup(tid, op, workbuf, 0x20000, fpath);
	printf("twl export: %08X %s\n\n",(int)res, res ? "FAILED!" : "SUCCESS!");
	
	return res;
}