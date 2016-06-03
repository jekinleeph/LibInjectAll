#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <elf.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>

#define SOINFO_NAME_LEN 128

struct soinfo
{
    char name[SOINFO_NAME_LEN];
    const Elf32_Phdr *phdr;
    int phnum;
    unsigned entry;
    unsigned base;
    unsigned size;

    int unused;  // DO NOT USE, maintained for compatibility.

    unsigned *dynamic;

    unsigned unused2; // DO NOT USE, maintained for compatibility
    unsigned unused3; // DO NOT USE, maintained for compatibility

    struct soinfo *next;
    unsigned flags;

    const char *strtab;
    Elf32_Sym *symtab;

    unsigned nbucket;
    unsigned nchain;
    unsigned *bucket;
    unsigned *chain;

    unsigned *plt_got;

    Elf32_Rel *plt_rel;
    unsigned plt_rel_count;

    Elf32_Rel *rel;
    unsigned rel_count;

    unsigned *preinit_array;
    unsigned preinit_array_count;

    unsigned *init_array;
    unsigned init_array_count;
    unsigned *fini_array;
    unsigned fini_array_count;

    void (*init_func)(void);
    void (*fini_func)(void);

};

#define LOG_TAG "HOOK"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)  

int g_isInit = 0;      
pthread_t g_hThread;   
#define LIB_APP_PATH  "/system/lib/libapp.so" 
// global function variable, save the address of strcmp of libapp.so  
int (*g_realstrcmp)(const char *s1, const char *s2);  

// replace function of libapp.so  
// e.g: replace strcmp of libapp.so with my_strcmp  
void replaceFunc(void *handle,const char *name, void* pNewFun, void** pOldFun )  
{  
   if(!handle)  
      return;  
        
   struct soinfo *si = (struct soinfo*)handle;     
   Elf32_Sym *symtab = si->symtab;    
   const char *strtab = si->strtab;    
   Elf32_Rel *rel = si->plt_rel;  
   unsigned count = si->plt_rel_count;   
   unsigned idx;   
  
   // these external functions that are called by libapp.so   
   // is in the plt_rel  
   for(idx=0; idx<count; idx++)   
   {    
      unsigned type = ELF32_R_TYPE(rel->r_info);    
      unsigned sym = ELF32_R_SYM(rel->r_info);    
      unsigned reloc = (unsigned)(rel->r_offset + si->base);    
      char *sym_name = (char *)(strtab + symtab[sym].st_name);   
        
      if(strcmp(sym_name, name)==0)   
      {   
         *pOldFun = (void *)*((unsigned*)reloc);   
          *((unsigned*)reloc)= pNewFun;  
         break;  
      }   
      rel++;    
   }   
}  

// my strcmp function  
int my_strcmp(const char *s1, const char *s2)  
{  
    if( g_realstrcmp != NULL )  
    {  
        int nRet = g_realstrcmp( s1, s2 );  
        printf("***%s: s1=%s, s2=%s\n",__FUNCTION__, s1, s2 );  
        return nRet;  
    }  
  
    return -1;  
}

// create a thread  
void* my_thread( void* pVoid )  
{  
    int sock;  
    sock = socket(AF_INET, SOCK_DGRAM, 0);  
    if( sock < -1 )  
    {  
      LOGD("create socket failed!\n");  
      return 0;  
    }  
  
    struct sockaddr_in addr_serv;    
    int len;    
    memset(&addr_serv, 0, sizeof(struct sockaddr_in));    
    addr_serv.sin_family = AF_INET;    
    addr_serv.sin_port = htons(9999);     
    addr_serv.sin_addr.s_addr = inet_addr("127.0.0.1");    
    len = sizeof(addr_serv);    
  
    int flags = fcntl( sock, F_GETFL, 0);   
    fcntl( sock, F_SETFL, flags | O_NONBLOCK);  
    int nPreState = -1;  
    unsigned char data=0;  
    while( 1 )  
    {  
        data++;  
        sendto( sock, &data,  sizeof( data ), 0, (struct sockaddr *)&addr_serv, sizeof( addr_serv ) );  
        usleep( 30000 );  
    }  
} 

int hook_entry(char * a){
	LOGD("Hook success, pid = %d\n", getpid());
	if( g_isInit == 1 )  
	{  
		LOGD("Already hooked func!");  
		return;  
	}  
	void* soHandle = NULL;  
	// the libapp.so is a .so of target process, and it call strcmp  
	soHandle  = dlopen( LIB_APP_PATH, RTLD_GLOBAL );  
	if( soHandle != NULL )  
	{  
		g_realstrcmp = NULL;  
		replaceFunc( soHandle, "strcmp", my_strcmp, (void**)&g_realstrcmp );  

		int ret = pthread_create( &g_hThread, NULL, my_thread, NULL );  
		if( ret != 0 )  
		{  
			LOGD("create thread error:%d", ret );  
		}
		g_isInit = 1;  
	}  
	return 0;
}

/*
#include <unistd.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <android/log.h>  
#include <EGL/egl.h>  
#include <GLES/gl.h>  
#include <elf.h>  
#include <fcntl.h>  
#include <sys/mman.h>  
  
#define LOG_TAG "DEBUG"  
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)    
  
EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = -1;  
  
EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface)  
{  
    LOGD("New eglSwapBuffers\n");  
    if (old_eglSwapBuffers == -1)  
        LOGD("error\n");  
    return old_eglSwapBuffers(dpy, surface);  
}  
  
void* get_module_base(pid_t pid, const char* module_name)  
{  
    FILE *fp;  
    long addr = 0;  
    char *pch;  
    char filename[32];  
    char line[1024];  
  
    if (pid < 0) {  
        // self process
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);  
    } else {  
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);  
    }  
  
    fp = fopen(filename, "r");  
  
    if (fp != NULL) {  
        while (fgets(line, sizeof(line), fp)) {  
            if (strstr(line, module_name)) {  
                pch = strtok( line, "-" );  
                addr = strtoul( pch, NULL, 16 );  
  
                if (addr == 0x8000)  
                    addr = 0;  
  
                break;  
            }  
        }  
  
        fclose(fp) ;  
    }  
  
    return (void *)addr;  
}  
  
#define LIBSF_PATH  "/system/lib/libsurfaceflinger.so"    
int hook_eglSwapBuffers()    
{    
    old_eglSwapBuffers = eglSwapBuffers;    
    LOGD("Orig eglSwapBuffers = %p\n", old_eglSwapBuffers);    
    void * base_addr = get_module_base(getpid(), LIBSF_PATH);    
    LOGD("libsurfaceflinger.so address = %p\n", base_addr);    
  
    int fd;    
    fd = open(LIBSF_PATH, O_RDONLY);    
    if (-1 == fd) {    
        LOGD("error\n");    
        return -1;    
    }    
  
    Elf32_Ehdr ehdr;    
    read(fd, &ehdr, sizeof(Elf32_Ehdr));    
  
    unsigned long shdr_addr = ehdr.e_shoff;      
    int shnum = ehdr.e_shnum;      
    int shent_size = ehdr.e_shentsize;      
    unsigned long stridx = ehdr.e_shstrndx;      
  
    Elf32_Shdr shdr;    
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);      
    read(fd, &shdr, shent_size);      
  
    char * string_table = (char *)malloc(shdr.sh_size);      
    lseek(fd, shdr.sh_offset, SEEK_SET);      
    read(fd, string_table, shdr.sh_size);    
    lseek(fd, shdr_addr, SEEK_SET);      
  
    int i;      
    uint32_t out_addr = 0;    
    uint32_t out_size = 0;    
    uint32_t got_item = 0;  
    int32_t got_found = 0;    
  
    for (i = 0; i < shnum; i++) {      
        read(fd, &shdr, shent_size);      
        if (shdr.sh_type == SHT_PROGBITS) {    
            int name_idx = shdr.sh_name;      
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0   
                    || strcmp(&(string_table[name_idx]), ".got") == 0) {      
                out_addr = base_addr + shdr.sh_addr;      
                out_size = shdr.sh_size;      
                LOGD("out_addr = %lx, out_size = %lx\n", out_addr, out_size);    
  
                for (i = 0; i < out_size; i += 4) {      
                    got_item = *(uint32_t *)(out_addr + i);    
                    if (got_item  == old_eglSwapBuffers) {      
                        LOGD("Found eglSwapBuffers in got\n");    
                        got_found = 1;  
  
                        uint32_t page_size = getpagesize();  
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));  
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);  
                        *(uint32_t *)(out_addr + i) = new_eglSwapBuffers;    
  
                        break;      
                    } else if (got_item == new_eglSwapBuffers) {      
                        LOGD("Already hooked\n");    
                        break;      
                    }      
                }     
                if (got_found)   
                    break;  
            }     
        }      
    }      
  
    free(string_table);      
    close(fd);    
}    
  
int hook_entry(char * a){  
    LOGD("Hook success\n");  
    LOGD("Start hooking\n");  
    hook_eglSwapBuffers();    
    return 0;  
}  
*/
