/* Bring in definitions for `_OS_X_`, `PATH_MAX` and `PATHSEPSTRING`, `jl_ptls_t`, etc... */
#include "../src/support/platform.h"
#include "../src/support/dirpath.h"

#ifdef _OS_WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#ifdef _OS_DARWIN_
#include <mach-o/dyld.h>
#endif
#ifdef _OS_FREEBSD_
#include <sys/sysctl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

#include <unistd.h>
#include <dlfcn.h>
#endif

// Borrow definitions from `julia.h`
#if defined(__GNUC__)
#  define JL_CONST_FUNC __attribute__((const))
#elif defined(_COMPILER_MICROSOFT_)
#  define JL_CONST_FUNC __declspec(noalias)
#else
#  define JL_CONST_FUNC
#endif


// Declarations from `loader_lib.c` and `loader_win_utils.c`
extern const char * get_exe_dir();
extern int load_repl(const char *, int, char **);
void print_stderr(const char * msg);
void print_stderr3(const char * msg1, const char * msg2, const char * msg3);

#ifdef _OS_WINDOWS_
LPWSTR *CommandLineToArgv(LPWSTR lpCmdLine, int *pNumArgs);
int wchar_to_utf8(const wchar_t * wstr, char *str, size_t maxlen);
int utf8_to_wchar(const char * str, wchar_t *wstr, size_t maxlen);
void setup_stdio(void);
#endif