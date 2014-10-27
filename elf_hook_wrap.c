#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_hook.h"

#define LIBRARY_ADDRESS_BY_HANDLE(dlhandle) ((NULL == dlhandle) ? \
NULL :  (void*)*(size_t const*)(dlhandle))

#if defined(LINECARD)
#define EH_LIBS_FILE_PREFIX     "/tmp/elf_hook."
#else
//#define EH_LIBS_FILE_PREFIX     "/nxos/tmp/elf_hook."
#define EH_LIBS_FILE_PREFIX     "/tmp/elf_hook."
#endif

static pid_t g_eh_self_pid = 0;
static char g_eh_libs_file[256] = { 0, };
static FILE *g_eh_libs_fp = NULL;
static void *g_eh_hndl_hooks = NULL;

// Per hook symbol data


static
int hook_module(const char *module_filename, const char *old_sym,
        fn_hook_data_t *hook_data, int is_self)
{
    void *handle = NULL, *base = NULL, *original = NULL;
    int rc = 0;

    dlerror();    /* Clear any existing error */
    if (is_self) {
        handle = dlopen(NULL, RTLD_LAZY);
    }
    else {
        handle = dlopen(module_filename, RTLD_LAZY);
        //handle = dlopen(module_filename, RTLD_NOLOAD | RTLD_LAZY);
    }
    if (NULL == handle) {
        fprintf(stderr, "Failed to open module \"%s\"!\n",
                module_filename);
        return -1;
    }

#if 0
    if (get_module_base_address(module_filename, handle, &base)) {
        fprintf(stderr, "Failed to get base address for module \"%s\"\n",
                module_filename);
        rc = -1;
        goto cln_out;
    }
#else
    base = LIBRARY_ADDRESS_BY_HANDLE(handle);
    if (is_self) {
        fprintf(stdout, "Self handle: %p, base: %p\n", handle, base);
    }
#endif

    original = elf_hook(module_filename, base, old_sym, hook_data->new_fn);
    if (NULL != original) {
        fprintf(stdout, "Redirected function \"%s\" in module \"%s\"\n",
                old_sym, module_filename);
        if (NULL == hook_data->old_fn) {
            hook_data->old_fn = original;

            // Now, set in the hook lib copy
            (hook_data->set_fn_ptr)(hook_data);
        }
    }

//cln_out:
    dlerror();    /* Clear any existing error */
    dlclose(handle);

    return rc;
}

int open_all_libs(void)
{
    char sys_str[256];

    g_eh_self_pid = getpid();
    snprintf(g_eh_libs_file, sizeof(g_eh_libs_file),
            EH_LIBS_FILE_PREFIX "%d", g_eh_self_pid);
    snprintf(sys_str, sizeof(sys_str),
            "cat /proc/%d/maps | cut -d ' ' -f 6- | tr -d [=' '=] | uniq"
            //" | grep '\/isan\/lib' > /tmp/elf_hook.%d",
            " | grep '\\.so' > %s",
            g_eh_self_pid, g_eh_libs_file);

    system(sys_str);

    g_eh_libs_fp = fopen(g_eh_libs_file, "r");
    if (g_eh_libs_fp == NULL) {
        return -1;
    }

    return 0;
}

int close_all_libs(void)
{
    fclose(g_eh_libs_fp);
    g_eh_libs_fp = NULL;

    unlink(g_eh_libs_file);

    return 0;
}

int open_hook(const char *hooklib_filename, const char *new_sym,
        const char *old_sym, fn_hook_data_t *hook_data)
{
    void *handle = NULL;
    void *sym = NULL;
    set_hook_data_fn_t set_fn_sym = NULL;
    char set_hook_data_fn[256];

    memset(hook_data, 0, sizeof(fn_hook_data_t));

    if (NULL != g_eh_hndl_hooks) {
        handle = g_eh_hndl_hooks;
        goto open_done;
    }

    dlerror();    /* Clear any existing error */
    handle = dlopen(hooklib_filename, RTLD_LAZY);
    if (NULL == handle) {
        fprintf(stderr, "Failed to open module \"%s\"!\n",
                hooklib_filename);
        return -1;
    }

    g_eh_hndl_hooks = handle;
open_done:

    dlerror();    /* Clear any existing error */
    sym = dlsym(handle, new_sym);
    if (sym == NULL) {
        fprintf(stderr, "Failed to lookup symbol \"%s\" in module \"%s\"\n",
                new_sym, hooklib_filename);
        return -2;
    }

    hook_data->new_fn = sym;

    snprintf(set_hook_data_fn, sizeof(set_hook_data_fn),
            "set_%s_hook_data", old_sym);

    dlerror();    /* Clear any existing error */
    set_fn_sym = (set_hook_data_fn_t) dlsym(handle, set_hook_data_fn);
    if (set_fn_sym == NULL) {
        fprintf(stderr, "Failed to lookup symbol \"%s\" in module \"%s\"\n",
                set_hook_data_fn, hooklib_filename);
    }
    else {
        hook_data->set_fn_ptr = set_fn_sym;
    }

    return 0;
}

int restore_original(fn_hook_data_t *hook_data)
{
    hook_data->new_fn = hook_data->old_fn;
    hook_data->old_fn = NULL;

    return 0;
}

int close_hook(const char *hooklib_filename)
{
    (void) hooklib_filename;

    if (NULL != g_eh_hndl_hooks) {
        dlerror();    /* Clear any existing error */
        dlclose(g_eh_hndl_hooks);
        g_eh_hndl_hooks = NULL;
    }

    return 0;
}

int hook_all_libs(const char *old_sym, fn_hook_data_t *hook_data)
{
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    if (fseek(g_eh_libs_fp, 0, SEEK_SET) != 0)
        fprintf(stderr, "Failed to set cursor to start of file \"%s\"\n",
                g_eh_libs_file);

    while ((read = getline(&line, &len, g_eh_libs_fp)) != -1) {
        //printf("Retrieved line of length %zu :\n", read);
        //printf("%d: ", line[read - 1]);

        // Change '\n' to '\0'
        line[read - 1] = '\0';
        //printf("%s\n", line);

        hook_module(line, old_sym, hook_data, 0);
    }
    if (line)
        free(line);

    return 0;
}

int hook_self_exec(const char *self_filename, const char *old_sym,
        fn_hook_data_t *hook_data)
{
    return hook_module(self_filename, old_sym, hook_data, 1);
}

