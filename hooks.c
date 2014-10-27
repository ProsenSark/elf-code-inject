#include <stdio.h>
#include <string.h>

#include "elf_hook.h"

static fn_hook_data_t gs_puts_data;

int set_puts_hook_data(const fn_hook_data_t *data)
{
    memcpy(&gs_puts_data, data, sizeof(fn_hook_data_t));

    return 0;
}

int hooked_puts(const char *s)
{
    typedef int (*puts_fn_t)(const char *s);
    int rc = 0;

    if (NULL == gs_puts_data.old_fn) {
        return EOF;
    }

    //rc = puts(s);  //calls the original puts() from libc.so because our main executable module called "test" is intact by hook
    //puts("is HOOKED!");
    rc = ((puts_fn_t) gs_puts_data.old_fn)(s);
    ((puts_fn_t) gs_puts_data.old_fn)("is HOOKED!");

    return rc;
}
