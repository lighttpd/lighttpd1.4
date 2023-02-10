/*
 * server_win32 - _WIN32 winsvc
 *
 * Copyright(c) 2023 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * intended for server.c to #include "server_win32.c"
 * - uses file-scoped static globals defined in server.c
 * - wraps server.c main()
 */
#include "first.h"

#include <winsvc.h>
#include <tchar.h>
#include <strsafe.h>


#if 0
static void SvcReportEvent (const LPTSTR szFunction)
{
    /*(XXX: would need separate event source message catalog for lighttpd)*/
    //HANDLE hEventSource = RegisterEventSource(NULL, "lighttpd");
    HANDLE hEventSource = OpenEventLogA(NULL, "System");
    if (NULL == hEventSource) return;

    TCHAR Buffer[1024];
    StringCchPrintf(Buffer, sizeof(Buffer), TEXT("%s GetLastError(%d)"),
                    szFunction, GetLastError());

    LPCTSTR lpszStrings[] = { "lighttpd", Buffer };
    ReportEvent(hEventSource,        // event log handle
                EVENTLOG_ERROR_TYPE, // event type
                0,                   // event category
                0x1, //SVC_ERROR     // event identifier
                NULL,                // no security identifier
                sizeof(lpszStrings)/sizeof(*lpszStrings), // lpszStrings size
                0,                   // no binary data
                lpszStrings,         // array of strings
                NULL);               // no binary data

    //DeregisterEventSource(hEventSource);
    CloseEventLog(hEventSource);
}
#endif


__attribute_cold__
__attribute_noinline__
static UINT lighttpd_ServiceCreate (int argc, char ** argv)
{
    /* https://learn.microsoft.com/en-us/windows/win32/services/svc-cpp */
    TCHAR szUnquotedPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szUnquotedPath, MAX_PATH)) {
        fprintf(stderr, "Can not install service (%lu)\n", GetLastError());
        return GetLastError();
    }

    /* Command: "C:\path\to\lighttpd.exe" -f "C:\path\to\lighttpd.conf" */
    /* In case the path contains a space, it must be quoted so that
     * it is correctly interpreted. For example,
     * "d:\my share\myservice.exe" should be specified as
     * ""d:\my share\myservice.exe"". */
    TCHAR szCommandLine[MAX_PATH*3+16];
    StringCbPrintf(szCommandLine, sizeof(szCommandLine),
                   TEXT("\"%s\" -f \"%sf\""),
                   szUnquotedPath, szUnquotedPath);
    const size_t len = _tcslen(szCommandLine);
    memcpy(szCommandLine+len-5, "conf", 4);
  #ifndef LIGHTTPD_STATIC
    StringCbPrintf(szCommandLine+len, sizeof(szCommandLine)-len,
                   TEXT(" -m \"%s.libs\""), szUnquotedPath-12);
  #endif

    SC_HANDLE schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!schSCM) {
        fprintf(stderr, "OpenSCManager failed (%lu)\n", GetLastError());
        return GetLastError();
    }

    /* LocalSystem is too powerful; this works but is overkill.
     * XXX: Recommended: dedicated account should be created and used.
     * "NT AUTHORITY\\NetworkService" might be used if files lighttpd.exe and
     * lighttpd.conf are installed in location accessible by NetWorkService acct
     */
    LPCSTR lpServiceStartName = ".\\LocalSystem";
    if (argc >= 4) {
        /* e.g. sc.exe config lighttpd obj= <AccountName> */
        if (0 == strcmp(argv[2], "obj="))
            lpServiceStartName = argv[3];
    }

    SC_HANDLE schSvc =
      CreateService(schSCM,
                    "lighttpd",
                    "lighttpd",
                    GENERIC_READ,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    szCommandLine,
                    NULL,
                    NULL,
                    NULL,
                    lpServiceStartName,
                    NULL);

    if (schSvc)
        printf("Service installed successfully\n");
    else
        fprintf(stderr, "CreateService failed (%lu)\n", GetLastError());

    if (schSvc) {
        char desc[] = "lighttpd web service";
        SERVICE_DESCRIPTIONA svc_desc = { desc };
        ChangeServiceConfig2A(schSvc, SERVICE_CONFIG_DESCRIPTION, &svc_desc);
        /*(ignore if setting Description fails)*/
    }

  #ifdef __MINGW32__
    /* lighttpd service will fail to start unless mingw libs are available.
     * Append mingw libs path to PATH in OS System Environment, or set custom
     * PATH for lighttpd service and then restart the lighttpd service:
     * In powershell:
     *   reg add HKLM\SYSTEM\CurrentControlSet\Services\lighttpd /f /v Environment /t REG_MULTI_SZ /d "PATH=$env:Path;C:\cygwin64\usr\x86_64-w64-mingw32\sys-root\mingw\bin"
     *   sc.exe start lighttpd
     * Replace PATH above as appropriate, and separate PATH elements using ';'.
     * Note: there is no REG_MULTI_EXPAND_SZ, so the resulting value must be
     * expanded (and can not use %SystemRoot% or %SYSTEM32% or %PATH%) */
  #endif

    CloseServiceHandle(schSvc);
    CloseServiceHandle(schSCM);
    return schSvc ? 0 : GetLastError();
}


__attribute_cold__
__attribute_noinline__
static UINT lighttpd_ServiceDelete (void)
{
    /* https://learn.microsoft.com/en-us/windows/win32/services/svcconfig-cpp */
    SC_HANDLE schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCM) {
        fprintf(stderr, "OpenSCManager failed (%lu)\n", GetLastError());
        return GetLastError();
    }

    SC_HANDLE schSvc = OpenService(schSCM, "lighttpd", DELETE);
    if (schSvc == NULL) {
        fprintf(stderr, "OpenService failed (%lu)\n", GetLastError());
        CloseServiceHandle(schSCM);
        return GetLastError();
    }

    BOOL rc = DeleteService(schSvc);
    if (rc)
        printf("Service removed successfully\n");
    else
        fprintf(stderr, "DeleteService failed (%lu)\n", GetLastError());

    CloseServiceHandle(schSvc);
    CloseServiceHandle(schSCM);
    return rc ? 0 : GetLastError();
}


static void signal_handler (int sig);

static void lighttpd_ServiceCtrlHandler (DWORD dwCtrl)
{
    switch (dwCtrl) {
      case SERVICE_CONTROL_PARAMCHANGE:
        signal_handler(SIGUSR1); /*(redefined to SIGBREAK)*/
        break;
      case SERVICE_CONTROL_STOP:
        signal_handler(SIGINT);
        break;
      case SERVICE_CONTROL_INTERROGATE:
      default:
        break;
    }
}


static SERVICE_STATUS_HANDLE hStatus;

__attribute_cold__
__attribute_noinline__
static void lighttpd_ServiceStatus (DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    if (!hStatus) return;

    DWORD dwControlsAccepted = SERVICE_ACCEPT_STOP;
    if (dwCurrentState == SERVICE_RUNNING)
        dwControlsAccepted |= SERVICE_ACCEPT_PARAMCHANGE;
    else if (dwCurrentState == SERVICE_START_PENDING)
        dwControlsAccepted = 0;

    static DWORD gSvcCheckPoint;
    DWORD dwCheckPoint =
      (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
        ? (gSvcCheckPoint = 0)
        : gSvcCheckPoint++;

    SERVICE_STATUS status = {
      SERVICE_WIN32_OWN_PROCESS,
      dwCurrentState,
      dwControlsAccepted,
      dwWin32ExitCode,
      0, /*dwServiceSpecificExitCode*/
      dwCheckPoint,
      dwWaitHint
    };
    SetServiceStatus(hStatus, &status);
}


#define server_status_running(srv) \
  lighttpd_ServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

#define server_status_stopping(srv) \
  DWORD dwWaitHint = (DWORD)(srv->graceful_expire_ts-log_monotonic_secs)*1000; \
  lighttpd_ServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, dwWaitHint + 1000);


#ifndef main
#define main main
#define server_main_win32 main
#endif
__attribute_cold__
int server_main_win32 (int argc, char ** argv);

static int svc_main_argc;
static char ** svc_main_argv;

__attribute_cold__
__attribute_noinline__
static void lighttpd_ServiceMain (DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors)
{
    /* service thread; not main(); params are not program startup argc, argv */
    hStatus = RegisterServiceCtrlHandlerA("lighttpd",
                                          lighttpd_ServiceCtrlHandler);
    if (!hStatus) return; /*(unexpected; can not continue)*/
    lighttpd_ServiceStatus(SERVICE_START_PENDING, NO_ERROR, 1000);

    int argc = svc_main_argc;    /* saved in lighttpd_ServiceCtrlDispatcher() */
    char ** argv = svc_main_argv;/* saved in lighttpd_ServiceCtrlDispatcher() */
    /* allow manual override by lighttpd Service Properties "Start parameters"*/
    if (dwNumServicesArgs > 1) {
        argc = (int)dwNumServicesArgs;
        argv = lpServiceArgVectors;
    }

    server_main_win32(argc, argv);

    lighttpd_ServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
    CloseHandle(hStatus);
    hStatus = NULL;
}


__attribute_cold__
__attribute_noinline__
static void lighttpd_ServiceCtrlDispatcher (int argc, char ** argv)
{
    if (argc >= 2 && 0 == strcmp(argv[1], "svc-create"))
        ExitProcess(lighttpd_ServiceCreate(argc, argv));
    if (argc == 2 && 0 == strcmp(argv[1], "svc-delete"))
        ExitProcess(lighttpd_ServiceDelete());

    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-' && strchr(argv[i], 'D')) /*(stay in foreground)*/
            return;
    }

    /* save original service start argc and argv for use by lighttpd_ServiceMain
     * since lighttpd_ServiceMain() thread is passed service name "lighttpd" and
     * argc == 1.  (This is a single-service application; using globals this way
     * is probably not appropriate for multi-service applications.) */
    svc_main_argc = argc;
    svc_main_argv = argv;

    static const SERVICE_TABLE_ENTRYA lighttpd_ServiceDispatchTable[] = {
      { "lighttpd", lighttpd_ServiceMain },
      { NULL, NULL }
    };
    UINT rc = StartServiceCtrlDispatcherA(lighttpd_ServiceDispatchTable)
      ? 0
      : GetLastError();
    /* https://learn.microsoft.com/en-us/windows/win32/services/debugging-a-service
     *  At times, it may be necessary to run a service as a console application
     *  for debugging purposes. In this scenario, the StartServiceCtrlDispatcher
     *  function will return ERROR_FAILED_SERVICE_CONTROLLER_CONNECT. Therefore,
     *  be sure to structure your code such that service-specific code is not
     *  called when this error is returned. */
    if (rc != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        ExitProcess(rc);
}


#include <signal.h>     /* sig_atomic_t */
void fdevent_win32_init (volatile sig_atomic_t *ptr);

#include <fcntl.h>      /* _O_BINARY */
#include <io.h>         /* _setmode() */
#include <stdlib.h>     /* _set_fmode() */
__attribute_cold__
int server_main_win32 (int argc, char ** argv)
{
    static int lighttpd_ServiceCtrlDispatcher_once;
    if (!lighttpd_ServiceCtrlDispatcher_once) {
        lighttpd_ServiceCtrlDispatcher_once = 1;
        lighttpd_ServiceCtrlDispatcher(argc, argv);
    }

    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);
    int rc = WSAStartup(wVersionRequested, &wsaData);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup() failed: %d\n", rc);
        return -1;
    }

    /* https://docs.microsoft.com/en-us/cpp/c-runtime-library/fmode?view=msvc-160 */
    /* https://sourceforge.net/p/mingw-w64/bugs/857/ */
    /*_set_fmode(_O_BINARY);*/
    _fmode = _O_BINARY;
    (void)_setmode(_fileno(stdin),  _O_BINARY);
    (void)_setmode(_fileno(stdout), _O_BINARY);
    (void)_setmode(_fileno(stderr), _O_BINARY);

    fdevent_win32_init(&handle_sig_child);

    rc = server_main(argc, argv);

    fdevent_win32_init(NULL);

    WSACleanup();
    return rc;
}
