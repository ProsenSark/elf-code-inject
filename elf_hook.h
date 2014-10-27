#pragma once

typedef struct fn_hook_data_s fn_hook_data_t;

typedef int (*set_hook_data_fn_t)(const fn_hook_data_t *data);

struct fn_hook_data_s {
    void *old_fn;
    void *new_fn;
    set_hook_data_fn_t set_fn_ptr;
};

#ifdef __cplusplus
extern "C"
{
#endif

int get_module_libraries(char const *module_filename);
int get_module_base_address(char const *module_filename, void *handle, void **base);
void *elf_hook(char const *library_filename, void const *library_address, char const *function_name, void const *substitution_address);

int open_all_libs(void);
int open_hook(const char *hooklib_filename, const char *new_sym,
        const char *old_sym, fn_hook_data_t *hook_data);
int restore_original(fn_hook_data_t *hook_data);

int hook_all_libs(const char *old_sym, fn_hook_data_t *hook_data);
int hook_self_exec(const char *self_filename, const char *old_sym,
        fn_hook_data_t *hook_data);

int close_hook(const char *hooklib_filename);
int close_all_libs(void);

#ifdef __cplusplus
}
#endif
