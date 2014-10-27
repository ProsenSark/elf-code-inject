#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <pthread.h>

#include "elf_hook.h"

void libtest1();  //from libtest1.so
void libtest2();  //from libtest2.so

int main(int argc, char *argv[])
{
    char *pwd = NULL;
    const char *fn_sym = "puts";
    fn_hook_data_t fn_data;
    char hooklib[256];

    (void) argc;

    puts("-----------------------------");
    libtest1();  //calls puts() from libc.so twice
    libtest2();  //calls puts() from libc.so twice
    puts("-----------------------------");

    pwd = getcwd(NULL, 0);
    if (NULL == pwd)
        return -1;

    snprintf(hooklib, sizeof(hooklib),
            "%s/libhooks.so", pwd);
    free(pwd);

    open_all_libs();
    // Hook it to new
    open_hook(hooklib, "hooked_puts", fn_sym,
            &fn_data);

    hook_all_libs(fn_sym, &fn_data);
    hook_self_exec(argv[0], fn_sym, &fn_data);

    puts("-----------------------------");
    libtest1();  //calls puts() from libc.so twice
    libtest2();  //calls puts() from libc.so twice
    puts("-----------------------------");

    // Restore back to original
    restore_original(&fn_data);

    hook_all_libs(fn_sym, &fn_data);
    hook_self_exec(argv[0], fn_sym, &fn_data);

    puts("-----------------------------");
    libtest1();  //calls puts() from libc.so twice
    libtest2();  //calls puts() from libc.so twice
    puts("-----------------------------");

    close_hook(hooklib);
    close_all_libs();

    //pthread_exit(NULL);     // To keep valgrind happy
    return 0;
}

