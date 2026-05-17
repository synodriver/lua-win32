#include "lua.h"
#include "lauxlib.h"

#include "Windows.h"
#include "tlhelp32.h"

#if defined(_WIN32) || defined(_WIN64)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif /* _WIN32 */

static int current_encoding = CP_UTF8;

static inline void
set_encoding(int e)
{
    current_encoding = e;
}

static inline int
get_encoding()
{
    return current_encoding;
}

static int
lset_encoding(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have one arg as int");
    }
    int e = (int) luaL_checkinteger(L, 1);
    set_encoding(e);
    return 0;
}

static int
lget_encoding(lua_State *L)
{
    int e = get_encoding();
    lua_pushinteger(L, e);
    return 1;
}

// copied from cpython
static WCHAR *FormatError(DWORD code)
{
    WCHAR *lpMsgBuf;
    DWORD n;
    n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       code,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
                       (LPWSTR) &lpMsgBuf,
                       0,
                       NULL);
    if (n)
    {
        while (iswspace(lpMsgBuf[n - 1]))
            --n;
        lpMsgBuf[n] = L'\0'; /* rstrip() */
    }
    return lpMsgBuf;
}

// convert
// @param index the char* index
// @return 0 if ok, -i on error. push wchar_t* as fulluserdata to the top of stack and it's length
static int
lMultiByteToWideChar(lua_State *L, int index)
{
    if (lua_type(L, index) != LUA_TSTRING)
    {
        return -1;
    }
    LPCCH s = (LPCCH) lua_tostring(L, index);
    int size_needed = MultiByteToWideChar(current_encoding, MB_COMPOSITE, s, -1, NULL, 0);
    size_needed += 10;
    LPWSTR buf = (LPWSTR) lua_newuserdata(L, size_needed * sizeof(WCHAR));
    int res = MultiByteToWideChar(current_encoding, MB_COMPOSITE, s, -1, buf, size_needed);
    if (res != 0)
    {
        lua_pushinteger(L, size_needed); /*ud, int*/
        return 0;
    }
    else
    {
        lua_pop(L, 1);
        return -1; // GetLastError
    }
}

static void
mod_to_tale(lua_State *L, MODULEENTRY32 *mod)
{
    lua_createtable(L, 0, 10); /*table*/
#define SETTABLEINT(name) lua_pushinteger(L, mod->name); \
    lua_setfield(L, -2, #name);
    SETTABLEINT(dwSize)
    SETTABLEINT(th32ModuleID)
    SETTABLEINT(th32ProcessID)
    SETTABLEINT(GlblcntUsage)
    SETTABLEINT(ProccntUsage)
    SETTABLEINT(modBaseSize)
#undef SETTABLEINT

#define SETTABLEPTR(name) lua_pushlightuserdata(L, mod->name); \
    lua_setfield(L, -2, #name);
    SETTABLEPTR(modBaseAddr)
    SETTABLEPTR(hModule)
#undef SETTABLEPTR

#define SETTABLESTR(name) lua_pushstring(L, (const char*)mod->name); \
    lua_setfield(L, -2, #name);
    SETTABLESTR(szModule)
    SETTABLESTR(szExePath)

#undef SETTABLESTR
}

static void
process_to_table(lua_State *L, PROCESSENTRY32 *process)
{
    lua_createtable(L, 0, 10); /*table*/
#define SETTABLEINT(name) lua_pushinteger(L, process->name); \
    lua_setfield(L, -2, #name);
    SETTABLEINT(dwSize)
    SETTABLEINT(cntUsage)
    SETTABLEINT(th32ProcessID)
    SETTABLEINT(th32DefaultHeapID)
    SETTABLEINT(th32ModuleID)
    SETTABLEINT(cntThreads)
    SETTABLEINT(th32ParentProcessID)
    SETTABLEINT(pcPriClassBase)
    SETTABLEINT(dwFlags)

#undef SETTABLEINT


#define SETTABLESTR(name) lua_pushstring(L, (const char*)process->name); \
    lua_setfield(L, -2, #name);
    SETTABLESTR(szExeFile)

#undef SETTABLESTR
}

static void
thread_to_table(lua_State *L, THREADENTRY32 *thread)
{
    lua_createtable(L, 0, 7); /*table*/
#define SETTABLEINT(name) lua_pushinteger(L, thread->name); \
    lua_setfield(L, -2, #name);
    SETTABLEINT(dwSize)
    SETTABLEINT(cntUsage)
    SETTABLEINT(th32ThreadID)
    SETTABLEINT(th32OwnerProcessID)
    SETTABLEINT(tpBasePri)
    SETTABLEINT(tpDeltaPri)
    SETTABLEINT(dwFlags)

#undef SETTABLEINT
}


static int
lmoduleiter(lua_State *L)
{
    MODULEENTRY32 *mod = (MODULEENTRY32 *) lua_touserdata(L, lua_upvalueindex(1));
    HANDLE snap_shot = (HANDLE) lua_touserdata(L, lua_upvalueindex(2));
    int entered = lua_toboolean(L, lua_upvalueindex(3));
    if (!entered)
    {
        if (!Module32First(snap_shot, mod))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else
        {
            mod_to_tale(L, mod);
        }
        lua_pushboolean(L, 1); /*tb, bool*/
        lua_copy(L, -1, lua_upvalueindex(3));
        lua_pop(L, 1); /*tb*/
    }
    else
    {
        if (!Module32Next(snap_shot, mod))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else
        {
            mod_to_tale(L, mod);
        }
    }
    return 1;
}

static int
liter_module(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have a pid");
    }
    DWORD pid = (DWORD) luaL_checkinteger(L, 1);
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
    {
        return luaL_error(L, "failed to call CreateToolhelp32Snapshot: %s", FormatError(GetLastError()));
    }
    MODULEENTRY32 *mod = (MODULEENTRY32 *) lua_newuserdata(L, sizeof(MODULEENTRY32));
    mod->dwSize = sizeof(MODULEENTRY32);

    lua_pushlightuserdata(L, snap_shot); /*MODULEENTRY32W, snap_shot*/
    lua_pushboolean(L, 0); /*MODULEENTRY32W, snap_shot, entered: int*/
    lua_pushcclosure(L, &lmoduleiter, 3);
    return 1;
}

static int
lprocessiter(lua_State *L)
{

    PROCESSENTRY32 *process = (PROCESSENTRY32 *) lua_touserdata(L, lua_upvalueindex(1));
    HANDLE snap_shot = (HANDLE) lua_touserdata(L, lua_upvalueindex(2));
    int entered = lua_toboolean(L, lua_upvalueindex(3));
    if (!entered)
    {
        if (!Process32First(snap_shot, process))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else
        {
            process_to_table(L, process);
        }
        lua_pushboolean(L, 1); /*tb, bool*/
        lua_copy(L, -1, lua_upvalueindex(3));
        lua_pop(L, 1); /*tb*/
    }
    else
    {
        if (!Process32Next(snap_shot, process))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else
        {
            process_to_table(L, process);
        }
    }
    return 1;
}

static int
liter_process(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have a pid");
    }
    DWORD pid = (DWORD) luaL_checkinteger(L, 1);
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
    {
        return luaL_error(L, "failed to call CreateToolhelp32Snapshot: %s", FormatError(GetLastError()));
    }
    PROCESSENTRY32 *process = (PROCESSENTRY32 *) lua_newuserdata(L, sizeof(PROCESSENTRY32));
    process->dwSize = sizeof(PROCESSENTRY32);

    lua_pushlightuserdata(L, snap_shot); /*PROCESSENTRY32W, snap_shot*/
    lua_pushboolean(L, 0); /*PROCESSENTRY32W, snap_shot, entered: int*/
    lua_pushcclosure(L, &lprocessiter, 3);
    return 1;
}

static int
lthreaditer(lua_State *L)
{
    THREADENTRY32 *thread = (THREADENTRY32 *) lua_touserdata(L, lua_upvalueindex(1));
    HANDLE snap_shot = (HANDLE) lua_touserdata(L, lua_upvalueindex(2));
    int entered = lua_toboolean(L, lua_upvalueindex(3));
    if (!entered)
    {
        if (!Thread32First(snap_shot, thread))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else
        {
            thread_to_table(L, thread);
        }
        lua_pushboolean(L, 1); /*tb, bool*/
        lua_copy(L, -1, lua_upvalueindex(3));
        lua_pop(L, 1); /*tb*/
    }
    else
    {
        if (!Thread32Next(snap_shot, thread))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else
        {
            thread_to_table(L, thread);
        }
    }
    return 1;
}

static int
liter_thread(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have a pid");
    }
    DWORD pid = (DWORD) luaL_checkinteger(L, 1);
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
    {
        return luaL_error(L, "failed to call CreateToolhelp32Snapshot: %s", FormatError(GetLastError()));
    }
    THREADENTRY32 *thread = (THREADENTRY32 *) lua_newuserdata(L, sizeof(THREADENTRY32));
    thread->dwSize = sizeof(THREADENTRY32);

    lua_pushlightuserdata(L, snap_shot); /*THREADENTRY32, snap_shot*/
    lua_pushboolean(L, 0); /*THREADENTRY32, snap_shot, entered: int*/
    lua_pushcclosure(L, &lthreaditer, 3);
    return 1;
}

static int
llockworkstation(lua_State *L)
{
    lua_pushboolean(L, LockWorkStation());
    return 1;
}

static int
lGetCurrentProcessId(lua_State *L)
{
    lua_pushinteger(L, GetCurrentProcessId());
    return 1;
}

static int
lgetcursorpos(lua_State *L)
{
    POINT p;
    GetCursorPos(&p);
    lua_pushinteger(L, p.x);
    lua_pushinteger(L, p.y);
    return 2;
}

static int
lsetcursorpos(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        return luaL_error(L, "must have x and y");
    }
    int x = (int) luaL_checkinteger(L, 1);
    int y = (int) luaL_checkinteger(L, 2);
    lua_pushboolean(L, SetCursorPos(x, y));
    return 1;
}

static int
lmouse_event(lua_State *L)
{
    if (lua_gettop(L) != 5)
    {
        return luaL_error(L, "must have x and y");
    }
    DWORD flag = (DWORD) luaL_checkinteger(L, 1);
    DWORD x = (DWORD) luaL_checkinteger(L, 2);
    DWORD y = (DWORD) luaL_checkinteger(L, 3);
    DWORD data = (DWORD) luaL_checkinteger(L, 4);
    ULONG_PTR extra = (ULONG_PTR) luaL_checkinteger(L, 5);
    mouse_event(flag, x, y, data, extra);
    return 0;
}


static int
lsleep(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have a time as milliseconds");
    }
    DWORD s = (DWORD) luaL_checkinteger(L, 1);
    Sleep(s);
    return 0;
}

static int
lgetmodulehandle(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have a module name, nil represent self");
    }
    LPCSTR param = NULL;
    switch (lua_type(L, 1))
    {
        case LUA_TNIL:
        {
            break;
        }
        case LUA_TSTRING:
        {
            param = (LPCSTR) lua_tostring(L, 1);
            break;
        }
        default:
            return luaL_error(L, "wrong type, must be string or nil");
    }
    HMODULE m = GetModuleHandleA(param);
//    GetModuleHandleExA()
    if (m == NULL)
    {
        lua_pushnil(L);
    }
    else
    {
        lua_pushlightuserdata(L, m);
    }
    return 1;
}

static int
lgetmodulehandlew(lua_State *L)
{
    if (lua_gettop(L) != 1)
    {
        return luaL_error(L, "must have a module name, nil represent self");
    }
    LPCWSTR param = NULL;

    switch (lua_type(L, 1))
    {
        case LUA_TNIL:
        {
            break;
        }
        case LUA_TSTRING:
        {
            if (lMultiByteToWideChar(L, 1) != 0)
            {
                return luaL_error(L, "failed to call MultiByteToWideChar: %s", FormatError(GetLastError()));
            }
            param = (LPCWSTR) lua_touserdata(L, -2);
            break;
        }
        default:
            return luaL_error(L, "wrong type, must be string or nil");
    }
    HMODULE m = GetModuleHandleW(param);
//    GetModuleHandleExA()
    if (m == NULL)
    {
        lua_pushnil(L);
    }
    else
    {
        lua_pushlightuserdata(L, m);
    }
    return 1;
}


static int
lfindwindow(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        return luaL_error(L, "must have a lpClassName and lpWindowName, can be nil");
    }
    LPCSTR lpClassName = NULL;
    switch (lua_type(L, 1))
    {
        case LUA_TNIL:
        {
            break;
        }
        case LUA_TSTRING:
        {
            lpClassName = (LPCSTR) lua_tostring(L, 1);
            break;
        }
        default:
            return luaL_error(L, "lpClassName must be string or nil");
    }
    LPCSTR lpWindowName = NULL;
    switch (lua_type(L, 2))
    {
        case LUA_TNIL:
        {
            break;
        }
        case LUA_TSTRING:
        {
            lpWindowName = (LPCSTR) lua_tostring(L, 2);
            break;
        }
        default:
            return luaL_error(L, "lpWindowName must be string or nil");
    }

    HWND window = FindWindowA(lpClassName, lpWindowName);
    if (window == NULL)
    {
        lua_pushnil(L);
    }
    else
    {
        lua_pushlightuserdata(L, window);
    }
    return 1;
}


static int
lfindwindow_w(lua_State *L)
{
    if (lua_gettop(L) != 2)
    {
        return luaL_error(L, "must have a lpClassName and lpWindowName, can be nil");
    }
    LPCWSTR lpClassName = NULL;
    switch (lua_type(L, 1))
    {
        case LUA_TNIL:
        {
            break;
        }
        case LUA_TSTRING:
        {
            if (lMultiByteToWideChar(L, 1) != 0)
            {
                return luaL_error(L, "failed to call MultiByteToWideChar: %s", FormatError(GetLastError()));
            }
            lpClassName = (LPCWSTR) lua_touserdata(L, -2); /*str, str, wchar ud, int*/
            lua_pop(L, 1); /*str, str, wchar ud*/
            break;
        }
        default:
            return luaL_error(L, "lpClassName must be string or nil");
    }
    LPCWSTR lpWindowName = NULL;
    switch (lua_type(L, 2))
    {
        case LUA_TNIL:
        {
            break;
        }
        case LUA_TSTRING:
        {
            if (lMultiByteToWideChar(L, 2) != 0)
            {
                return luaL_error(L, "failed to call MultiByteToWideChar: %s", FormatError(GetLastError()));
            }
            lpWindowName = (LPCWSTR) lua_touserdata(L, -2); /*str, str, wchar ud, wchar ud, int*/
            lua_pop(L, 1); /*str, str, wchar ud, wchar ud*/
            break;
        }
        default:
            return luaL_error(L, "lpClassName must be string or nil");
    }

    HWND window = FindWindowW(lpClassName, lpWindowName);
    if (window == NULL)
    {
        lua_pushnil(L);
    }
    else
    {
        lua_pushlightuserdata(L, window);
    }
    return 1;
}

static int
lget_client_rect(lua_State* L)
{
    if (lua_type(L, 1) != LUA_TLIGHTUSERDATA)
    {
        return luaL_error(L, "arg1 must be HWND");
    }
    HWND window = (HWND)lua_touserdata(L, 1);
    RECT rect;
    GetClientRect(window, &rect);
    lua_pushinteger(L, rect.left);
    lua_pushinteger(L, rect.top);
    lua_pushinteger(L, rect.right);
    lua_pushinteger(L, rect.bottom);
    return 4;
}

static int
lget_dc(lua_State* L)
{
    if (lua_type(L, 1) != LUA_TLIGHTUSERDATA)
    {
        return luaL_error(L, "arg1 must be HWND");
    }
    HWND window = (HWND)lua_touserdata(L, 1);
    HDC ret = GetDC(window);
    lua_pushlightuserdata(L, ret);
    return 1;
}

static int
lcreate_compatible_dc(lua_State* L)
{
    if (lua_type(L, 1) != LUA_TLIGHTUSERDATA)
    {
        return luaL_error(L, "arg1 must be HDC");
    }
    HDC dc = (HDC)lua_touserdata(L, 1);
    HDC cdc = CreateCompatibleDC(dc);
    lua_pushlightuserdata(L, cdc);
    return 1;
}

static int
lcreate_compatible_bitmap(lua_State* L)
{
    if(lua_gettop(L)!=3)
    {
        return luaL_error(L, "must have 3 args, hdc, cx and cy");
    }
    HDC dc = (HDC)lua_touserdata(L, 1);
    int cx = (int)luaL_checkinteger(L, 2);
    int cy = (int)luaL_checkinteger(L, 3);
    HBITMAP bitmap = CreateCompatibleBitmap(dc, cx, cy);
    lua_pushlightuserdata(L, bitmap);
    return 1;
}

static int
lselect_object(lua_State* L)
{
    if(lua_gettop(L)!=2)
    {
        return luaL_error(L, "must have 2 args: hdc and HGDIOBJ");
    }
    HDC dc = (HDC)lua_touserdata(L, 1);
    HGDIOBJ gdi = (HGDIOBJ)lua_touserdata(L, 2);
    HGDIOBJ ret = SelectObject(dc, gdi);
    lua_pushlightuserdata(L, ret);
    return 1;
}

static int
lbitblt(lua_State* L)
{
    if(lua_gettop(L)!=9)
    {
        return luaL_error(L, "must have 9 args: hdc, x, y, c, cy, hdcsrc, x1, y1 and rop");
    }
    HDC hdc = (HDC)lua_touserdata(L, 1);
    int x = (int)luaL_checkinteger(L, 2);
    int y = (int)luaL_checkinteger(L, 3);
    int cx = (int)luaL_checkinteger(L, 4);
    int cy = (int)luaL_checkinteger(L, 5);
    HDC hdcsrc = (HDC)lua_touserdata(L, 6);
    int x1 = (int)luaL_checkinteger(L, 7);
    int y1 = (int)luaL_checkinteger(L, 8);
    DWORD rop = (DWORD)luaL_checkinteger(L, 9);
    BOOL ret = BitBlt(hdc, x, y, cx, cy, hdcsrc, x1, y1, rop);
    lua_pushboolean(L, ret);
    return 1;
}

static int
lget_bitmap_bits(lua_State *L)
{
    if(lua_gettop(L)!=2)
    {
        return luaL_error(L, "must have 2 args: bitmap and total_bytes");
    }
    HBITMAP bitmap = (HBITMAP)lua_touserdata(L, 1);
    int total_bytes = (int)luaL_checkinteger(L, 2);
    void* bits = lua_newuserdata(L, total_bytes);
    GetBitmapBits(bitmap, total_bytes, bits);
    lua_pushlstring(L, (const char*)bits, total_bytes);
    return 1;
}

static int
ldelete_object(lua_State *L)
{
    if(lua_gettop(L)!=1)
    {
        return luaL_error(L, "must have 1 arg");
    }
    HGDIOBJ gdi = (HGDIOBJ)lua_touserdata(L, 1);
    lua_pushboolean(L, DeleteObject(gdi));
    return 1;
}


static int
lisdebuggerpresent(lua_State *L)
{
    /* unix
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

    int is_debugger_attached() {
        // PTRACE_TRACEME: 允许调试器附加到当前进程
        // 如果当前进程已经被调试器附加，ptrace会返回-1并设置errno
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
            return 1; // 被调试器附加
        }
        return 0; // 没有被调试器附加
    }
    */
    if (lua_gettop(L) != 0)
    {
        return luaL_error(L, "no args is needed");
    }
    lua_pushboolean(L, IsDebuggerPresent());
    return 1;
}

static int
lread_clipboard(lua_State *L)
{
    if (!OpenClipboard(NULL))
    {
        lua_pushnil(L);
        return 1;
    }
    HANDLE hdata = GetClipboardData(CF_TEXT);
    if (hdata == NULL)
    {
        CloseClipboard();
        lua_pushnil(L);
        return 1;
    }
    const char *text = (const char *) GlobalLock(hdata);
    if (text == NULL)
    {
        CloseClipboard();
        lua_pushnil(L);
        return 1;
    }
    lua_pushstring(L, text);
    GlobalUnlock(hdata);
    CloseClipboard();
    return 1;
}

static luaL_Reg lua_funcs[] = {
        {"set_encoding", &lset_encoding},
        {"get_encoding", &lget_encoding},
        {"iter_module", &liter_module},
        {"iter_process", &liter_process},
        {"iter_thread", &liter_thread},
        {"lock_workstation", &llockworkstation},
        {"get_current_process_id", &lGetCurrentProcessId},
        {"get_cursor_pos", &lgetcursorpos},
        {"set_cursor_pos", &lsetcursorpos},
        {"mouse_event", &lmouse_event},
        {"sleep", &lsleep},
        {"get_module_handle", &lgetmodulehandle},
        {"get_module_handle_w", &lgetmodulehandlew},
        {"find_window", &lfindwindow},
        {"find_window_w", &lfindwindow_w},
        {"get_client_rect",&lget_client_rect},
        {"get_dc", &lget_dc},
        {"create_compatible_dc", &lcreate_compatible_dc},
        {"create_compatible_bitmap", &lcreate_compatible_bitmap},
        {"select_object", &lselect_object},
        {"bitblt", &lbitblt},
        {"get_bitmap_bits", &lget_bitmap_bits},
        {"delete_object", &ldelete_object},
        {"is_debugger_present", &lisdebuggerpresent},
        {"read_clipboard", &lread_clipboard},
        {NULL, NULL}
};

DLLEXPORT int luaopen_win32(lua_State *L)
{
    luaL_newlib(L, lua_funcs);
#define ADDINTCONST(name) lua_pushinteger(L, name); \
    lua_setfield(L, -2, #name);
    ADDINTCONST(MOUSEEVENTF_MOVE)
    ADDINTCONST(MOUSEEVENTF_LEFTDOWN)
    ADDINTCONST(MOUSEEVENTF_LEFTUP)
    ADDINTCONST(MOUSEEVENTF_RIGHTDOWN)
    ADDINTCONST(MOUSEEVENTF_RIGHTUP)
    ADDINTCONST(MOUSEEVENTF_MIDDLEDOWN)
    ADDINTCONST(MOUSEEVENTF_MIDDLEUP)
    ADDINTCONST(MOUSEEVENTF_XDOWN)
    ADDINTCONST(MOUSEEVENTF_XUP)
    ADDINTCONST(MOUSEEVENTF_WHEEL)
    ADDINTCONST(MOUSEEVENTF_HWHEEL)
    ADDINTCONST(MOUSEEVENTF_MOVE_NOCOALESCE)
    ADDINTCONST(MOUSEEVENTF_VIRTUALDESK)
    ADDINTCONST(MOUSEEVENTF_ABSOLUTE)
    ADDINTCONST(CP_ACP)
    ADDINTCONST(CP_OEMCP)
    ADDINTCONST(CP_MACCP)
    ADDINTCONST(CP_THREAD_ACP)
    ADDINTCONST(CP_SYMBOL)
    ADDINTCONST(CP_UTF7)
    ADDINTCONST(CP_UTF8)
#undef ADDINTCONST
    return 1;
}