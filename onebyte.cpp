#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <conio.h>

// sigs for latest legacy build
static const int PAT_WH[] = { 0x33,0xC0,0x83,0xFA,-1,0xB9,0x20 };
static const int PAT_RADAR[] = { 0x74,0x15,0x8B,0x47,0x08,0x8D,0x4F,0x08 };

static HANDLE    g_proc = NULL;
static uintptr_t g_clientBase = 0;
static size_t    g_clientSize = 0;

static std::atomic<bool> g_whOn{ false };
static std::atomic<bool> g_radOn{ false };
static std::atomic<bool> g_csgo{ false };
static std::atomic<bool> g_quit{ false };
static std::atomic<bool> g_cdWh{ false }; // cooldown
static std::atomic<bool> g_cdRad{ false };

static auto g_whTime = std::chrono::steady_clock::time_point{};
static auto g_radTime = std::chrono::steady_clock::time_point{};

DWORD FindProcId(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe))
        do { if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; } } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

bool FindModule(DWORD pid, const char* modName, uintptr_t& base, size_t& sz) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    bool found = false;
    if (Module32First(snap, &me))
        do {
            if (_stricmp(me.szModule, modName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                sz = me.modBaseSize;
                found = true; break;
            }
        } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return found;
}

// dump whole module to scan
std::vector<BYTE> ReadMod(HANDLE proc, uintptr_t base, size_t sz) {
    std::vector<BYTE> buf(sz, 0);
    SIZE_T n = 0;
    ReadProcessMemory(proc, (LPCVOID)base, buf.data(), sz, &n);
    return buf;
}

// simple byte pattern scan, -1 = wildcard
ptrdiff_t ScanPattern(const std::vector<BYTE>& data, const int* pat, size_t patLen) {
    for (size_t i = 0; i + patLen <= data.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < patLen; ++j)
            if (pat[j] != -1 && data[i + j] != (BYTE)pat[j]) { ok = false; break; }
        if (ok) return (ptrdiff_t)i;
    }
    return -1;
}

bool ReadByte(uintptr_t addr, BYTE& val) {
    SIZE_T n = 0;
    return ReadProcessMemory(g_proc, (LPCVOID)addr, &val, 1, &n) && n == 1;
}

bool WriteByte(uintptr_t addr, BYTE val) {
    SIZE_T n = 0;
    return WriteProcessMemory(g_proc, (LPVOID)addr, &val, 1, &n) && n == 1;
}

bool Attach() {
    DWORD pid = FindProcId("csgo.exe");
    if (!pid) return false;
    HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!proc) return false;
    uintptr_t base = 0; size_t sz = 0;
    if (!FindModule(pid, "client.dll", base, sz)) { CloseHandle(proc); return false; }
    g_proc = proc; g_clientBase = base; g_clientSize = sz;
    return true;
}

void Detach() {
    if (g_proc) { CloseHandle(g_proc); g_proc = NULL; }
    g_clientBase = 0; g_clientSize = 0;
    g_whOn = false; g_radOn = false;
}

static const char* ERR_CSGO = "make sure CS:GO is running";

bool TryEnsureAttached() {
    if (g_csgo && g_proc) return true;
    if (Attach()) { g_csgo = true; return true; }
    return false;
}

const char* ToggleWallhack() {
    auto now = std::chrono::steady_clock::now();
    // 3 sec cooldown
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_whTime).count() < 3000) {
        g_cdWh = true; return nullptr;
    }
    g_cdWh = false;
    if (!TryEnsureAttached()) return ERR_CSGO;
    auto data = ReadMod(g_proc, g_clientBase, g_clientSize);
    ptrdiff_t off = ScanPattern(data, PAT_WH, 7);
    if (off < 0) return "pattern not found";
    uintptr_t addr = g_clientBase + off + 4; // skip first 4 bytes of sig
    BYTE cur = 0;
    if (!ReadByte(addr, cur)) return "read error";
    BYTE nv = (cur == 1) ? 2 : 1; // flip r_drawothermodels
    if (!WriteByte(addr, nv)) return "write error";
    g_whOn = !g_whOn.load();
    g_whTime = now;
    return nullptr;
}

const char* ToggleRadar() {
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_radTime).count() < 3000) {
        g_cdRad = true; return nullptr;
    }
    g_cdRad = false;
    if (!TryEnsureAttached()) return ERR_CSGO;
    auto data = ReadMod(g_proc, g_clientBase, g_clientSize);
    ptrdiff_t off = ScanPattern(data, PAT_RADAR, 8);
    if (off < 0) return "pattern not found";
    uintptr_t addr = g_clientBase + off - 1; // byte right before sig
    BYTE cur = 0;
    if (!ReadByte(addr, cur)) return "read error";
    BYTE nv = (cur != 0) ? 0 : 2; // toggle radar reveal
    if (!WriteByte(addr, nv)) return "write error";
    g_radOn = !g_radOn.load();
    g_radTime = now;
    return nullptr;
}

void DisableAll() {
    if (g_whOn)  ToggleWallhack();
    if (g_radOn) ToggleRadar();
}

void PrintUI(const char* msg = nullptr);

// checks if csgo is still alive + handles cooldown timers
void StatusThread() {
    while (!g_quit) {
        if (g_proc) {
            BYTE tmp = 0; SIZE_T n = 0;
            bool alive = ReadProcessMemory(g_proc, (LPCVOID)g_clientBase, &tmp, 1, &n) && n == 1;
            if (!alive) { Detach(); g_csgo = false; PrintUI(); }
        }

        bool wh_expired = g_cdWh && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - g_whTime).count() >= 3000;
        bool rad_expired = g_cdRad && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - g_radTime).count() >= 3000;
        if (wh_expired) { g_cdWh = false; PrintUI(); }
        if (rad_expired) { g_cdRad = false; PrintUI(); }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void ClearScreen() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(h, &info);
    DWORD sz = info.dwSize.X * info.dwSize.Y;
    DWORD written;
    COORD origin = { 0,0 };
    FillConsoleOutputCharacter(h, ' ', sz, origin, &written);
    FillConsoleOutputAttribute(h, info.wAttributes, sz, origin, &written);
    SetConsoleCursorPosition(h, origin);
}

void SetColor(WORD attr) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}

void PrintUI(const char* msg) {
    ClearScreen();
    SetColor(0x07);
    printf("OneByte v1.0\n\n");

    printf("  wallhack : ");
    if (g_whOn) { SetColor(0x0A); printf("on"); }
    else { SetColor(0x08); printf("off"); }
    if (g_cdWh) { SetColor(0x0E); printf("  wait"); }
    SetColor(0x07); printf("\n");

    printf("  radar    : ");
    if (g_radOn) { SetColor(0x0A); printf("on"); }
    else { SetColor(0x08); printf("off"); }
    if (g_cdRad) { SetColor(0x0E); printf("  wait"); }
    SetColor(0x07); printf("\n");

    printf("\n");
    printf("  1  toggle wallhack\n");
    printf("  2  toggle radar\n");
    if (g_csgo) printf("  0  unload\n");
    printf("\n");

    if (msg) {
        SetColor(0x0E);
        printf("  %s\n\n", msg);
        SetColor(0x07);
    }

    fflush(stdout);
}

int main() {
    // prevent multiple instances
    HANDLE mutex = CreateMutexA(NULL, TRUE, "OneByte_mutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(mutex); return 0; }

    SetConsoleTitle("OneByte");

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO ci; GetConsoleCursorInfo(hOut, &ci);
    ci.bVisible = FALSE; SetConsoleCursorInfo(hOut, &ci);

    // fixed window size to avoid scrollbars
    SMALL_RECT wr = { 0, 0, 39, 13 };
    SetConsoleWindowInfo(hOut, TRUE, &wr);
    COORD cs = { 40, 14 };
    SetConsoleScreenBufferSize(hOut, cs);

    std::thread statusTh(StatusThread);
    PrintUI();

    while (!g_quit) {
        int ch = _getch();
        if (ch == 0 || ch == 224) { _getch(); continue; } // skip arrow keys etc

        if (ch == '1') {
            const char* err = ToggleWallhack();
            if (!g_quit) PrintUI(err);
        }
        else if (ch == '2') {
            const char* err = ToggleRadar();
            if (!g_quit) PrintUI(err);
        }
        else if (ch == '0' && g_csgo) {
            DisableAll();
            g_quit = true;
        }
    }

    statusTh.join();
    Detach();
    SetColor(0x07);
    ClearScreen();
    printf("unloaded.\n");
    Sleep(800);
    return 0;
}
