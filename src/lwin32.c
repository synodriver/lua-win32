#include "lua.h"
#include "lauxlib.h"

#include "Windows.h"
#include "tlhelp32.h"

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#elif
#define DLLEXPORT
#endif /* _WIN32 */

static void
mod_to_tale(lua_State* L, MODULEENTRY32* mod)
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
process_to_tale(lua_State *L, PROCESSENTRY32* process)
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
thread_to_tale(lua_State *L, THREADENTRY32* thread)
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
lmoduleiter(lua_State* L)
{
    MODULEENTRY32* mod = (MODULEENTRY32*)lua_touserdata(L, lua_upvalueindex(1));
    HANDLE snap_shot = (HANDLE)lua_touserdata(L, lua_upvalueindex(2));
    int entered = lua_toboolean(L, lua_upvalueindex(3));
    if(!entered)
    {
        if(!Module32First(snap_shot, mod))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else{
            mod_to_tale(L, mod);
        }
        lua_pushboolean(L, 1); /*tb, bool*/
        lua_copy(L, -1, lua_upvalueindex(3));
        lua_pop(L ,1); /*tb*/
    }
    else
    {
        if(!Module32Next(snap_shot, mod))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else{
            mod_to_tale(L, mod);
        }
    }
    return 1;
}

static int
liter_module(lua_State* L)
{
    if(lua_gettop(L)!=1)
    {
        return luaL_error(L, "must have a pid");
    }
    DWORD pid = (DWORD) luaL_checkinteger(L, 1);
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
    {
        return luaL_error(L, "failed to call CreateToolhelp32Snapshot: %d", GetLastError());
    }
    MODULEENTRY32* mod = (MODULEENTRY32*)lua_newuserdata(L, sizeof(MODULEENTRY32));
    mod->dwSize = sizeof(MODULEENTRY32);

    lua_pushlightuserdata(L, snap_shot); /*MODULEENTRY32W, snap_shot*/
    lua_pushboolean(L, 0); /*MODULEENTRY32W, snap_shot, entered: int*/
    lua_pushcclosure(L, &lmoduleiter, 3);
    return 1;
}

static int
lprocessiter(lua_State* L)
{

    PROCESSENTRY32* process = (PROCESSENTRY32*)lua_touserdata(L, lua_upvalueindex(1));
    HANDLE snap_shot = (HANDLE)lua_touserdata(L, lua_upvalueindex(2));
    int entered = lua_toboolean(L, lua_upvalueindex(3));
    if(!entered)
    {
        if(!Process32First(snap_shot, process))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else{
            process_to_tale(L, process);
        }
        lua_pushboolean(L, 1); /*tb, bool*/
        lua_copy(L, -1, lua_upvalueindex(3));
        lua_pop(L ,1); /*tb*/
    }
    else
    {
        if(!Process32Next(snap_shot, process))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else{
            process_to_tale(L, process);
        }
    }
    return 1;
}

static int
liter_process(lua_State* L)
{
    if(lua_gettop(L)!=1)
    {
        return luaL_error(L, "must have a pid");
    }
    DWORD pid = (DWORD) luaL_checkinteger(L, 1);
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
    {
        return luaL_error(L, "failed to call CreateToolhelp32Snapshot: %d", GetLastError());
    }
    PROCESSENTRY32* process = (PROCESSENTRY32*)lua_newuserdata(L, sizeof(PROCESSENTRY32));
    process->dwSize = sizeof(PROCESSENTRY32);

    lua_pushlightuserdata(L, snap_shot); /*PROCESSENTRY32W, snap_shot*/
    lua_pushboolean(L, 0); /*PROCESSENTRY32W, snap_shot, entered: int*/
    lua_pushcclosure(L, &lprocessiter, 3);
    return 1;
}

static int
lthreaditer(lua_State* L)
{
    THREADENTRY32* thread = (THREADENTRY32*)lua_touserdata(L, lua_upvalueindex(1));
    HANDLE snap_shot = (HANDLE)lua_touserdata(L, lua_upvalueindex(2));
    int entered = lua_toboolean(L, lua_upvalueindex(3));
    if(!entered)
    {
        if(!Thread32First(snap_shot, thread))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else{
            thread_to_tale(L, thread);
        }
        lua_pushboolean(L, 1); /*tb, bool*/
        lua_copy(L, -1, lua_upvalueindex(3));
        lua_pop(L ,1); /*tb*/
    }
    else
    {
        if(!Thread32Next(snap_shot, thread))
        {
            lua_pushnil(L);
            CloseHandle(snap_shot);
        }
        else{
            thread_to_tale(L, thread);
        }
    }
    return 1;
}

static int
liter_thread(lua_State* L)
{
    if(lua_gettop(L)!=1)
    {
        return luaL_error(L, "must have a pid");
    }
    DWORD pid = (DWORD) luaL_checkinteger(L, 1);
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (snap_shot == INVALID_HANDLE_VALUE)
    {
        return luaL_error(L, "failed to call CreateToolhelp32Snapshot: %d", GetLastError());
    }
    THREADENTRY32* thread = (THREADENTRY32*)lua_newuserdata(L, sizeof(THREADENTRY32));
    thread->dwSize = sizeof(THREADENTRY32);

    lua_pushlightuserdata(L, snap_shot); /*THREADENTRY32, snap_shot*/
    lua_pushboolean(L, 0); /*THREADENTRY32, snap_shot, entered: int*/
    lua_pushcclosure(L, &lthreaditer, 3);
    return 1;
}

static int
llockworkstation(lua_State* L)
{
    lua_pushboolean(L, LockWorkStation());
    return 1;
}

static int
lGetCurrentProcessId(lua_State* L)
{
    lua_pushinteger(L, GetCurrentProcessId());
    return 1;
}

static luaL_Reg lua_funcs[] = {
        {"iter_module", &liter_module},
        {"iter_process", &liter_process},
        {"iter_thread", &liter_thread},
        {"lock_workstation", &llockworkstation},
        {"get_current_process_id", &lGetCurrentProcessId},
        {NULL, NULL}
};

DLLEXPORT int luaopen_win32(lua_State *L)
{
    luaL_newlib(L, lua_funcs);
    return 1;
}