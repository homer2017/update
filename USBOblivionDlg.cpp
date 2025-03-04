// USBOblivionDlg.cpp
#include "stdafx.h"
#include "USBOblivion.h"
#include "USBOblivionDlg.h"
#include <string> // Thêm để sử dụng std::to_wstring (C++11 trở lên)

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CUSBOblivionDlg::CUSBOblivionDlg(CWnd* pParent /*=NULL*/) noexcept
    : CDialog(CUSBOblivionDlg::IDD, pParent)
    , m_hIcon(AfxGetApp()->LoadIcon(IDR_MAINFRAME))
    , m_bEnable(FALSE)
    , m_bAuto(FALSE)
    , m_bSave(TRUE)
    , m_bRestorePoint(TRUE)
    , m_bElevation(FALSE)
    , m_bSilent(FALSE)
    , m_bReboot(TRUE)
    , m_bCloseExplorer(TRUE)
    , m_nSelected(-1)
    , m_InitialRect(0, 0, 0, 0)
    , m_nDrives(GetLogicalDrives())
    , m_bRunning(false)
    , m_pReportList(new CLogList)
    , m_bClearBrowser(FALSE)
    , m_bClearWifi(FALSE)
    , m_bClearApps(FALSE)
{
}

CUSBOblivionDlg::~CUSBOblivionDlg()
{
    locker_holder oLock(&m_pSection);

    while (!m_pReportList->IsEmpty())
    {
        delete m_pReportList->RemoveHead();
    }
}

void CUSBOblivionDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);

    DDX_Control(pDX, IDC_REPORT, m_pReport);
    DDX_Check(pDX, IDC_ENABLE, m_bEnable);
    DDX_Check(pDX, IDC_SAVE, m_bSave);
    DDX_Check(pDX, IDC_REBOOT, m_bReboot);
    DDX_Check(pDX, IDC_EXPLORER, m_bCloseExplorer);
    DDX_Check(pDX, IDC_CLEAR_BROWSER, m_bClearBrowser);
    DDX_Check(pDX, IDC_CLEAR_WIFI, m_bClearWifi);
    DDX_Check(pDX, IDC_CLEAR_APPS, m_bClearApps);
}

void CUSBOblivionDlg::CopyToClipboard(const CString& sData)
{
    if (OpenClipboard())
    {
        if (EmptyClipboard())
        {
            size_t nLen = (size_t)(sData.GetLength() + 1) * sizeof(TCHAR);
            if (HGLOBAL hGlob = GlobalAlloc(GMEM_FIXED, nLen))
            {
                CopyMemory((char*)hGlob, (char*)(LPCTSTR)sData, nLen);
                if (SetClipboardData(CF_UNICODETEXT, hGlob) == nullptr)
                {
                    GlobalFree(hGlob);
                }
            }
        }
        CloseClipboard();
    }
}

BEGIN_MESSAGE_MAP(CUSBOblivionDlg, CDialog)
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_WM_SIZE()
    ON_WM_GETMINMAXINFO()
    ON_WM_DESTROY()
    ON_NOTIFY(NM_RCLICK, IDC_REPORT, &CUSBOblivionDlg::OnNMRClickReport)
    ON_COMMAND(ID_COPY, &CUSBOblivionDlg::OnCopy)
    ON_COMMAND(ID_COPY_ALL, &CUSBOblivionDlg::OnCopyAll)
    ON_WM_HELPINFO()
    ON_WM_DEVICECHANGE()
    ON_WM_TIMER()
    ON_BN_CLICKED(IDC_ENABLE, &CUSBOblivionDlg::OnBnClickedEnable)
END_MESSAGE_MAP()

BOOL CUSBOblivionDlg::OnInitDialog()
{
    // Kiểm tra bản quyền trước khi khởi tạo giao diện
    if (!CheckLicense())
    {
        MessageBox(_T("Invalid or expired license. Program will exit."), _T("License Error"), MB_OK | MB_ICONERROR);
        EndDialog(IDCANCEL);
        return FALSE;
    }

    CDialog::OnInitDialog();

    ShowWindow((m_bAuto && m_bSilent) ? SW_HIDE : SW_SHOWNORMAL);
    CenterWindow();

    m_sDeleteKeyString = LoadString(IDS_DELETE_KEY);
    m_sDeleteValueString = LoadString(IDS_DELETE_VALUE);

    GetWindowRect(m_InitialRect);

    m_CtrlsResize.SetParentWnd(this);
    m_CtrlsResize.AddControl(IDC_REPORT, BIND_LEFT | BIND_RIGHT | BIND_TOP | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDOK, BIND_RIGHT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDCANCEL, BIND_RIGHT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_ENABLE, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_SAVE, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_REBOOT, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_EXPLORER, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_CLEAR_BROWSER, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_CLEAR_WIFI, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.AddControl(IDC_CLEAR_APPS, BIND_LEFT | BIND_BOTTOM);
    m_CtrlsResize.FixControls();

    SetIcon(m_hIcon, TRUE);
    SetIcon(m_hIcon, FALSE);

    CString sBinaryPath;
    GetModuleFileName(nullptr, sBinaryPath.GetBuffer(1024), 1024);
    sBinaryPath.ReleaseBuffer();

    CString sTitle = LoadString(AFX_IDS_APP_TITLE);
    if (DWORD dwSize = GetFileVersionInfoSize(sBinaryPath, &dwSize))
    {
        CAutoVectorPtr< BYTE > pBuffer(new BYTE[dwSize]);
        if (pBuffer)
        {
            if (GetFileVersionInfo(sBinaryPath, 0, dwSize, pBuffer))
            {
                VS_FIXEDFILEINFO* pTable = nullptr;
                if (VerQueryValue(pBuffer, _T("\\"), (VOID**)&pTable, (UINT*)&dwSize))
                {
                    sTitle.AppendFormat(_T(" %u.%u.%u.%u"),
                        (WORD)(pTable->dwFileVersionMS >> 16), (WORD)(pTable->dwFileVersionMS & 0xFFFF),
                        (WORD)(pTable->dwFileVersionLS >> 16), (WORD)(pTable->dwFileVersionLS & 0xFFFF));
                }
            }
        }
    }
#ifdef WIN64
    sTitle += _T(" (64-bit)");
#else
    sTitle += _T(" (32-bit)");
#endif
    SetWindowText(sTitle);

    CRect rc;
    m_pReport.GetClientRect(&rc);
    m_pReport.InsertColumn(0, _T(""), LVCFMT_LEFT, rc.Width() - GetSystemMetrics(SM_CXVSCROLL) - 4);
    m_pReport.SetExtendedStyle(m_pReport.GetExtendedStyle() | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    static const WORD nIcons[] =
    {
        IDI_INF, IDI_WARN, IDI_ERR, IDI_SEARCH, IDI_DONE,
        IDR_MAINFRAME, IDI_REGEDIT, IDI_LOCK, IDI_EJECT
    };
    m_oImages.Create(16, 16, ILC_COLOR32 | ILC_MASK, 0, _countof(nIcons)) ||
        m_oImages.Create(16, 16, ILC_COLOR24 | ILC_MASK, 0, _countof(nIcons)) ||
        m_oImages.Create(16, 16, ILC_COLOR16 | ILC_MASK, 0, _countof(nIcons));
    for (int i = 0; i < _countof(nIcons); ++i)
    {
        m_oImages.Add((HICON)LoadImage(AfxGetResourceHandle(),
            MAKEINTRESOURCE(nIcons[i]), IMAGE_ICON, 16, 16, LR_SHARED));
    }
    m_pReport.SetImageList(&m_oImages, LVSIL_SMALL);

    theApp.m_Loc.Translate(GetSafeHwnd(), CUSBOblivionDlg::IDD);

    Log(IDS_WARNING, Warning);

    if (!m_bEnable)
    {
        m_bReboot = FALSE;
    }

    UpdateData(FALSE);

    GetDlgItem(IDOK)->SendMessage(BCM_SETSHIELD, 0, !IsProcessElevated());
    SetDlgItemText(IDOK, LoadString(m_bEnable ? IDS_CLEAN : IDS_SIMULATE));

    if (m_bAuto || m_bElevation)
        PostMessage(WM_COMMAND, IDOK);

    SetTimer(1, 250, nullptr);

    return TRUE;
}

void CUSBOblivionDlg::OnDestroy()
{
    KillTimer(1);

    CDialog::OnDestroy();
}

void CUSBOblivionDlg::OnSize(UINT nType, int cx, int cy)
{
    CDialog::OnSize(nType, cx, cy);

    if (IsWindow(m_pReport.GetSafeHwnd()))
    {
        m_CtrlsResize.OnSize();

        CRect rc;
        m_pReport.GetClientRect(&rc);
        m_pReport.SetColumnWidth(0, rc.Width() - 4);
    }
}

void CUSBOblivionDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI)
{
    lpMMI->ptMinTrackSize.x = m_InitialRect.Width();
    lpMMI->ptMinTrackSize.y = m_InitialRect.Height();

    CDialog::OnGetMinMaxInfo(lpMMI);
}

void CUSBOblivionDlg::OnPaint()
{
    if (IsIconic())
    {
        CPaintDC dc(this);
        SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;
        dc.DrawIcon(x, y, m_hIcon);
    }
    else
        CDialog::OnPaint();
}

HCURSOR CUSBOblivionDlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(m_hIcon);
}

void CUSBOblivionDlg::OnOK()
{
    CWaitCursor wc;

    UpdateData();

    m_pReport.DeleteAllItems();

    GetDlgItem(IDC_ENABLE)->EnableWindow(FALSE);
    GetDlgItem(IDC_SAVE)->EnableWindow(FALSE);
    GetDlgItem(IDC_REBOOT)->EnableWindow(FALSE);
    GetDlgItem(IDC_EXPLORER)->EnableWindow(FALSE);
    GetDlgItem(IDOK)->EnableWindow(FALSE);
    GetDlgItem(IDCANCEL)->EnableWindow(FALSE);

    if (IsRunAsAdmin() || m_bElevation)
    {
        m_bRunning = true;
        startRunThread();

        // Cập nhật số lần sử dụng sau khi chạy thành công
        UpdateLicenseUsage();
        return;
    }
    else if (!m_bElevation)
    {
        Log(IDS_AS_ADMIN, Lock);

        CString sParams = _T("-elevation");
        if (m_bAuto)
            sParams += _T(" -auto");
        if (m_bEnable)
            sParams += _T(" -enable");
        if (!m_bSave)
            sParams += _T(" -nosave");
        if (!m_bRestorePoint)
            sParams += _T(" -norestorepoint");
        if (!m_bCloseExplorer)
            sParams += _T(" -noexplorer");
        if (!m_bReboot)
            sParams += _T(" -norestart");
        if (m_bSilent)
            sParams += _T(" -silent");
        if (m_bClearBrowser)
            sParams += _T(" -clearbrowser");
        if (m_bClearWifi)
            sParams += _T(" -clearwifi");
        if (m_bClearApps)
            sParams += _T(" -clearapps");
        sParams.AppendFormat(_T(" -lang:%x"), (int)theApp.m_Loc.GetLang());

        CString sPath;
        GetModuleFileName(nullptr, sPath.GetBuffer(MAX_PATH + 1), MAX_PATH);
        sPath.ReleaseBuffer();

        SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
        sei.lpVerb = _T("runas");
        sei.lpFile = sPath;
        sei.lpParameters = sParams;
        sei.hwnd = GetSafeHwnd();
        sei.nShow = (m_bAuto && m_bSilent) ? SW_HIDE : SW_SHOWNORMAL;

        if (ShellExecuteEx(&sei))
        {
            CDialog::OnOK();
            return;
        }
    }

    GetDlgItem(IDC_ENABLE)->EnableWindow(TRUE);
    GetDlgItem(IDC_SAVE)->EnableWindow(TRUE);
    GetDlgItem(IDC_REBOOT)->EnableWindow(TRUE);
    GetDlgItem(IDC_EXPLORER)->EnableWindow(TRUE);
    GetDlgItem(IDOK)->EnableWindow(TRUE);
    GetDlgItem(IDCANCEL)->EnableWindow(TRUE);

    Log(IDS_RUN_DONE, Done);

    if (m_bAuto)
        CDialog::OnOK();

    // Cập nhật số lần sử dụng sau khi chạy thành công
    UpdateLicenseUsage();
}

void CUSBOblivionDlg::OnCancel()
{
    if (m_bRunning)
        MessageBeep(MB_ICONHAND);
    else
        CDialog::OnCancel();
}

void CUSBOblivionDlg::RunThread()
{
    VERIFY(SUCCEEDED(CoInitializeEx(0, COINIT_MULTITHREADED)));

    if (PrepareBackup())
    {
        if (!RunAsSystem())
            Run();
    }

    FinishBackup();

    Reboot();

    if (!m_bReboot && m_bCloseExplorer)
    {
        StartExplorer();
    }

    Log(IDS_RUN_DONE, Done);

    CoUninitialize();
}

BOOL CUSBOblivionDlg::RunAsSystem()
{
    CAccessToken oToken;
    if (oToken.GetProcessToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY))
    {
        if (!oToken.EnablePrivilege(SE_DEBUG_NAME))
            TRACE(_T("EnablePrivilege(SE_DEBUG_NAME) error: %d\n"), GetLastError());

        if (!oToken.EnablePrivilege(SE_TAKE_OWNERSHIP_NAME))
            TRACE(_T("EnablePrivilege(SE_TAKE_OWNERSHIP_NAME) error: %d\n"), GetLastError());
        if (!oToken.EnablePrivilege(SE_SECURITY_NAME))
            TRACE(_T("EnablePrivilege(SE_SECURITY_NAME) error: %d\n"), GetLastError());

        if (!oToken.EnablePrivilege(SE_UNDOCK_NAME))
            TRACE(_T("EnablePrivilege(SE_UNDOCK_NAME) error: %d\n"), GetLastError());
        if (!oToken.EnablePrivilege(SE_LOAD_DRIVER_NAME))
            TRACE(_T("EnablePrivilege(SE_LOAD_DRIVER_NAME) error: %d\n"), GetLastError());
    }
    else
        TRACE(_T("CAccessToken::GetProcessToken error: %d\n"), GetLastError());

    const LPCTSTR szTargets[] = { _T("lsass.exe"), _T("smss.exe"), _T("csrss.exe"), _T("services.exe"),  _T("winlogon.exe") };

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE)
    {
        for (int i = 0; i < _countof(szTargets); ++i)
        {
            if (Process32First(hProcessSnap, &pe32))
            {
                do
                {
                    if (pe32.th32ProcessID == 0)
                        continue;

                    LPCTSTR szProcessName = PathFindFileName(pe32.szExeFile);
                    if (CmpStrI(szProcessName, szTargets[i]))
                    {
                        TRACE(_T("Found process: %s (PID: %d)\n"), szProcessName, pe32.th32ProcessID);

                        if (RunAsProcess(pe32.th32ProcessID))
                        {
                            CloseHandle(hProcessSnap);
                            return TRUE;
                        }
                    }
                } while (Process32Next(hProcessSnap, &pe32));
            }
            else
                TRACE(_T("Process32First error: %u\n"), GetLastError());
        }
        CloseHandle(hProcessSnap);
    }
    else
        TRACE(_T("CreateToolhelp32Snapshot(Process) error: %u\n"), GetLastError());

    Log(IDS_ERROR_PROCESS_ACCESS, Error);

    return FALSE;
}

BOOL CUSBOblivionDlg::RunAsProcess(DWORD dwProcessID)
{
    BOOL bResult = FALSE;

    if (HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID))
    {
        if (HANDLE hToken = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE))
        {
            if (ImpersonateLoggedOnUser(hToken))
            {
                bResult = TRUE;

                Log(IDS_RUN_IMPERSONATE, Lock);

                Run();

                RevertToSelf();
            }
            else
                TRACE(_T("ImpersonateLoggedOnUser error: %u (PID: %d)\n"), GetLastError(), dwProcessID);

            CloseHandle(hToken);
        }
        else
            TRACE(_T("OpenProcessToken error: %u (PID: %d)\n"), GetLastError(), dwProcessID);

        CloseHandle(hProcess);
    }

    return bResult;
}

void CUSBOblivionDlg::Log(UINT nID, UINT nType)
{
    Log(LoadString(nID), nType);
}

void CUSBOblivionDlg::Log(const CString& sText, UINT nType)
{
    TRACE("[LOG] %s\r\n", (LPCSTR)CT2A((LPCTSTR)sText));

    locker_holder oLock(&m_pSection);

    m_pReportList->AddTail(new CLogItem(sText, nType));

    if (!m_sLog.IsEmpty())
    {
        TRY
        {
            CFile file(m_sLog, CFile::modeCreate | CFile::modeNoTruncate | CFile::modeWrite | CFile::shareDenyNone);

            file.SeekToEnd();

            if (file.GetLength() == 0)
                file.Write(_T("\xfeff"), 2);

            file.Write(sText, (UINT)(sText.GetLength() * sizeof(TCHAR)));
            file.Write(_T("\r\n"), (UINT)(2 * sizeof(TCHAR)));
        }
            CATCH_ALL(e)
        {
            DELETE_EXCEPTION(e);
        }
        END_CATCH_ALL
    }
}

bool CUSBOblivionDlg::EjectDrive(TCHAR DriveLetter)
{
    CString msg;

    if (DriveLetter < _T('A') || DriveLetter > _T('Z'))
        return false;

    TCHAR szRootPath[] = _T("X:\\");
    szRootPath[0] = DriveLetter;
    TCHAR szDevicePath[] = _T("X:");
    szDevicePath[0] = DriveLetter;
    TCHAR szVolumeAccessPath[] = _T("\\\\.\\X:");
    szVolumeAccessPath[4] = DriveLetter;

    HANDLE hVolume = CreateFile(szVolumeAccessPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVolume == INVALID_HANDLE_VALUE)
        return false;

    DWORD DeviceNumber = (DWORD)-1;
    STORAGE_DEVICE_NUMBER sdn = {};
    DWORD dwBytesReturned = 0;
    if (DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof(sdn), &dwBytesReturned, nullptr))
    {
        DeviceNumber = sdn.DeviceNumber;
    }
    CloseHandle(hVolume);

    if (DeviceNumber == (DWORD)-1)
        return false;

    UINT DriveType = GetDriveType(szRootPath);

    TCHAR szDosDeviceName[MAX_PATH] = {};
    if (!QueryDosDevice(szDevicePath, szDosDeviceName, MAX_PATH))
        return false;

    DEVINST DevInst = GetDrivesDevInstByDeviceNumber(DeviceNumber, DriveType, szDosDeviceName);
    if (!DevInst)
        return false;

    DEVINST DevParent = 0;
    if (CM_Get_Parent(&DevParent, DevInst, 0) != CR_SUCCESS)
        return false;

    msg.Format(LoadString(IDS_RUN_EJECT), DriveLetter);
    Log(msg, Eject);

    if (!m_bEnable)
        return true;

    for (int tries = 1; tries <= 3; ++tries)
    {
        PNP_VETO_TYPE VetoType = PNP_VetoTypeUnknown;
        TCHAR szVetoName[MAX_PATH] = {};

        if (CM_Request_Device_Eject(DevParent, &VetoType, szVetoName, MAX_PATH, 0) == CR_SUCCESS && VetoType == PNP_VetoTypeUnknown)
        {
            msg.Format(LoadString(IDS_DISK_UNMOUNT), DriveLetter);
            Log(msg);
            return true;
        }

        Sleep(500);
    }

    msg.Format(LoadString(IDS_ERROR_EJECT), DriveLetter);
    Log(msg, Error);

    return false;
}

void CUSBOblivionDlg::Run()
{
    CString msg;

    Log(m_bEnable ? IDS_MODE_WORK : IDS_MODE_SIM);

    VERIFY(InitializeCOMSecurity());

    StopServices();

    EjectDrives();

    CloseExplorer();

    RESTOREPOINTINFOW RestorePtInfo = { BEGIN_SYSTEM_CHANGE, DEVICE_DRIVER_INSTALL };
    wcscpy_s(RestorePtInfo.szDescription, AfxGetAppName());
    STATEMGRSTATUS SMgrStatus = { ERROR_SERVICE_DISABLED };
    if (theApp.dyn_SRSetRestorePointW && m_bRestorePoint)
    {
        Log(IDS_RESTORE_POINT);

        if (theApp.dyn_SRSetRestorePointW(&RestorePtInfo, &SMgrStatus))
        {
            // OK
        }
        else if (SMgrStatus.nStatus == ERROR_SERVICE_DISABLED)
        {
            Log(IDS_DISABLED_RESTORE_POINT, Warning);
        }
        else
        {
            msg.Format(_T("%u"), SMgrStatus.nStatus);
            Log(LoadString(IDS_ERROR_RESTORE_POINT) + msg, Error);
        }
    }

    CleanFiles();

    CleanLogs();

    CleanLocalMachine();

    CleanMountedDevices();

    CleanWindowsSearch();

    CleanUsers();

    if (m_bClearBrowser)
        ClearBrowserHistory();
    if (m_bClearWifi)
        ClearWifiHistory();
    if (m_bClearApps)
        ClearRecentApps();

    static const struct
    {
        const HKEY hRoot;
        const TCHAR* const szSubKey;
        const TCHAR* const szValue;
        const DWORD dwType;
        const std::vector< BYTE > Data;
    }
    RestoreKeys[] =
    {
        { HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU"), _T("MRUListEx"), REG_BINARY, { 0xff, 0xff, 0xff, 0xff } },
        { HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU"), _T("NodeSlot"), REG_DWORD, { 0x01, 0x00, 0x00, 0x00 } },
        { HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU"), _T("NodeSlots"), REG_BINARY, { 0x02 } }
    };

    for (const auto& RestoreKey : RestoreKeys)
    {
        HKEY hKey;
        if (RegCreateKeyEx(RestoreKey.hRoot, RestoreKey.szSubKey, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
        {
            RegSetValueEx(hKey, RestoreKey.szValue, 0, RestoreKey.dwType, RestoreKey.Data.data(), (DWORD)RestoreKey.Data.size());
            RegCloseKey(hKey);
        }
    }

    RestorePtInfo.dwEventType = END_SYSTEM_CHANGE;
    if (theApp.dyn_SRSetRestorePointW && m_bRestorePoint && SMgrStatus.nStatus == ERROR_SUCCESS)
    {
        if (theApp.dyn_SRSetRestorePointW(&RestorePtInfo, &SMgrStatus))
        {
            Log(IDS_OK_RESTORE_POINT, Done);
        }
        else
        {
            msg.Format(_T("%u"), SMgrStatus.nStatus);
            Log(LoadString(IDS_ERROR_RESTORE_POINT) + msg, Error);
        }
    }
}

void CUSBOblivionDlg::DoDeleteFile(LPCTSTR szPath)
{
    CFileFind ff;
    BOOL bWorking = ff.FindFile(szPath);
    while (bWorking)
    {
        bWorking = ff.FindNextFile();
        const CString sPath = ff.GetFilePath();
        if (!ff.IsDirectory())
        {
            if (m_bEnable)
            {
                const CString sLongPath = CString(_T("\\\\?\\")) + sPath;
                if (::DeleteFile(sLongPath))
                {
                    Log(LoadString(IDS_DELETE_FILE) + sPath, Clean);
                }
                else
                {
                    if (::MoveFileEx(sLongPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
                    {
                        Log(LoadString(IDS_DELETE_FILE_BOOT) + sPath, Warning);
                    }
                    else
                    {
                        Log(LoadString(IDS_DELETE_FILE_ERROR) + sPath, Error);
                    }
                }
            }
            else
            {
                Log(LoadString(IDS_DELETE_FILE) + sPath, Clean);
            }
        }
    }
}

void CUSBOblivionDlg::DoDeleteLog(LPCTSTR szName)
{
    if (m_bEnable)
    {
        TCHAR szCommand[MAX_PATH] = _T("wevtutil.exe cl ");
        _tcscat_s(szCommand, szName);

        STARTUPINFO si = { sizeof(STARTUPINFO) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        PROCESS_INFORMATION pi = {};
        if (CreateProcess(nullptr, szCommand, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        if (HANDLE hLog = OpenEventLog(nullptr, szName))
        {
            DWORD dwCount = 0;
            if (GetNumberOfEventLogRecords(hLog, &dwCount) && dwCount > 1)
            {
                if (ClearEventLog(hLog, nullptr))
                {
                    Log(LoadString(IDS_RUN_LOG) + szName, Clean);
                }
                else
                {
                    CString msg;
                    msg.Format(_T("%s %s (%u)"), (LPCTSTR)LoadString(IDS_RUN_LOG_ERROR), szName, GetLastError());
                    Log(msg, Error);
                }
            }
            CloseEventLog(hLog);
        }
        else
        {
            CString msg;
            msg.Format(_T("%s %s (%u)"), (LPCTSTR)LoadString(IDS_RUN_LOG_ERROR), szName, GetLastError());
            Log(msg, Error);
        }
    }
    else
    {
        Log(LoadString(IDS_RUN_LOG) + szName, Clean);
    }
}

void CUSBOblivionDlg::OnNMRClickReport(NMHDR* pNMHDR, LRESULT* pResult)
{
    LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

    if (pNMItemActivate->iItem >= 0)
    {
        m_nSelected = pNMItemActivate->iItem;

        ClientToScreen(&pNMItemActivate->ptAction);

        CMenu oMenu;
        oMenu.LoadMenu(IDR_CONTEXT);
        theApp.m_Loc.Translate(oMenu.GetSafeHmenu(), IDR_CONTEXT);
        oMenu.GetSubMenu(0)->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON,
            pNMItemActivate->ptAction.x,
            pNMItemActivate->ptAction.y, this);
    }

    *pResult = 0;
}

void CUSBOblivionDlg::OnCopy()
{
    if (m_nSelected >= 0)
    {
        CopyToClipboard(m_pReport.GetItemText(m_nSelected, 0));
    }
}

void CUSBOblivionDlg::OnCopyAll()
{
    CString sData;
    int nCount = m_pReport.GetItemCount();
    for (int i = 0; i < nCount; ++i)
    {
        sData += m_pReport.GetItemText(i, 0) + _T("\r\n");
    }
    CopyToClipboard(sData);
}

BOOL CUSBOblivionDlg::OnHelpInfo(HELPINFO* /*pHelpInfo*/)
{
    CWaitCursor wc;

    ShellExecute(GetSafeHwnd(), nullptr, _T("https://t.me/Enjhad"), nullptr, nullptr, SW_SHOWDEFAULT);

    return TRUE;
}

BOOL CUSBOblivionDlg::OnDeviceChange(UINT /*nEventType*/, DWORD_PTR /*dwData*/)
{
    DWORD nDrives = GetLogicalDrives();
    if (m_nDrives != nDrives)
    {
        DWORD nMask = 1;
        for (TCHAR i = _T('A'); i <= _T('Z'); ++i, nMask <<= 1)
        {
            if (((m_nDrives ^ nDrives) & nMask) != 0)
            {
                CString msg;
                if ((m_nDrives & nMask) == 0)
                    msg.Format(LoadString(IDS_DISK_MOUNT), i);
                else
                    msg.Format(LoadString(IDS_DISK_UNMOUNT), i);
                Log(msg);
            }
        }

        m_nDrives = nDrives;
    }
    return TRUE;
}

void CUSBOblivionDlg::OnTimer(UINT_PTR nIDEvent)
{
    CAutoPtr< CLogList > pCopy;
    {
        locker_holder oLock(&m_pSection);
        if (!m_pReportList->IsEmpty())
        {
            pCopy.Attach(m_pReportList.Detach());
            m_pReportList.Attach(new CLogList);
        }
    }

    if (pCopy && !pCopy->IsEmpty())
    {
        DWORD nInsert = m_pReport.GetItemCount();
        do
        {
            CLogItem* pItem = pCopy->RemoveHead();
            m_pReport.InsertItem(nInsert++, pItem->first, pItem->second);
            delete pItem;
        } while (!pCopy->IsEmpty());

        m_pReport.EnsureVisible(nInsert - 1, FALSE);
    }

    if (m_bRunning && !m_threadRunThread.is_running())
    {
        m_bRunning = false;

        m_threadRunThread.close();

        GetDlgItem(IDC_ENABLE)->EnableWindow(TRUE);
        GetDlgItem(IDC_SAVE)->EnableWindow(TRUE);
        GetDlgItem(IDC_REBOOT)->EnableWindow(TRUE);
        GetDlgItem(IDC_EXPLORER)->EnableWindow(TRUE);
        GetDlgItem(IDOK)->EnableWindow(TRUE);
        GetDlgItem(IDCANCEL)->EnableWindow(TRUE);

        if (m_bAuto)
            CDialog::OnOK();
    }

    CDialog::OnTimer(nIDEvent);
}

INT_PTR CUSBOblivionDlg::DoModal()
{
    ASSERT(m_lpszTemplateName != nullptr || m_hDialogTemplate != nullptr ||
        m_lpDialogTemplate != nullptr);

    LPCDLGTEMPLATE lpDialogTemplate = m_lpDialogTemplate;
    HGLOBAL hDialogTemplate = m_hDialogTemplate;
    HINSTANCE hInst = AfxGetResourceHandle();
    if (m_lpszTemplateName != nullptr)
    {
        hInst = AfxFindResourceHandle(m_lpszTemplateName, RT_DIALOG);
        HRSRC hResource = ::FindResource(hInst, m_lpszTemplateName, RT_DIALOG);
        hDialogTemplate = LoadResource(hInst, hResource);
    }
    if (hDialogTemplate != nullptr)
        lpDialogTemplate = (LPCDLGTEMPLATE)LockResource(hDialogTemplate);

    if (lpDialogTemplate == nullptr)
        return -1;

    HWND hWndParent = PreModal();
    AfxUnhookWindowCreate();
    BOOL bEnableParent = FALSE;
#ifndef _AFX_NO_OLE_SUPPORT
    CWnd* pMainWnd = nullptr;
    BOOL bEnableMainWnd = FALSE;
#endif
    if (hWndParent && hWndParent != ::GetDesktopWindow() && ::IsWindowEnabled(hWndParent))
    {
        ::EnableWindow(hWndParent, FALSE);
        bEnableParent = TRUE;
#ifndef _AFX_NO_OLE_SUPPORT
        pMainWnd = AfxGetMainWnd();
        if (pMainWnd && pMainWnd->IsFrameWnd() && pMainWnd->IsWindowEnabled())
        {
            pMainWnd->EnableWindow(FALSE);
            bEnableMainWnd = TRUE;
        }
#endif
    }

    TRY
    {
        AfxHookWindowCreate(this);
        if (CreateDlgIndirect(lpDialogTemplate,
                        CWnd::FromHandle(hWndParent), hInst))
        {
            if (m_nFlags & WF_CONTINUEMODAL)
            {
                DWORD dwFlags = 0;
                if (GetStyle() & DS_NOIDLEMSG)
                    dwFlags |= MLF_NOIDLEMSG;
                VERIFY(RunModalLoop(dwFlags) == m_nModalResult);
            }

            if (m_hWnd != nullptr)
                SetWindowPos(nullptr, 0, 0, 0, 0, SWP_HIDEWINDOW |
                    SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_NOZORDER);
        }
    }
        CATCH_ALL(e)
    {
        DELETE_EXCEPTION(e);
        m_nModalResult = -1;
    }
    END_CATCH_ALL

#ifndef _AFX_NO_OLE_SUPPORT
        if (bEnableMainWnd)
            pMainWnd->EnableWindow(TRUE);
#endif
    if (bEnableParent)
        ::EnableWindow(hWndParent, TRUE);
    if (hWndParent != nullptr && ::GetActiveWindow() == m_hWnd)
        ::SetActiveWindow(hWndParent);

    DestroyWindow();
    PostModal();

    if (m_lpszTemplateName != nullptr || m_hDialogTemplate != nullptr)
        UnlockResource(hDialogTemplate);
    if (m_lpszTemplateName != nullptr)
        FreeResource(hDialogTemplate);

    return m_nModalResult;
}

void CUSBOblivionDlg::OnBnClickedEnable()
{
    UpdateData();

    SetDlgItemText(IDOK, LoadString(m_bEnable ? IDS_CLEAN : IDS_SIMULATE));

    m_bReboot = m_bEnable;

    UpdateData(FALSE);
}

void CUSBOblivionDlg::ClearBrowserHistory()
{
    Log(_T("Clearing browser history..."));

    CString chromePath;
    ExpandEnvironmentStrings(_T("%LocalAppData%\\Google\\Chrome\\User Data\\Default\\History"), chromePath.GetBuffer(MAX_PATH), MAX_PATH);
    chromePath.ReleaseBuffer();
    if (m_bEnable)
    {
        if (::DeleteFile(chromePath))
        {
            Log(_T("Deleted Chrome browsing history: ") + chromePath, Clean);
        }
        else
        {
            CString msg;
            msg.Format(_T("Failed to delete Chrome history: %s (%u)"), chromePath, GetLastError());
            Log(msg, Error);
        }
    }
    else
    {
        Log(_T("Simulation: Would delete Chrome history: ") + chromePath, Clean);
    }

    CString firefoxPath;
    ExpandEnvironmentStrings(_T("%AppData%\\Mozilla\\Firefox\\Profiles\\*.default-release\\places.sqlite"), firefoxPath.GetBuffer(MAX_PATH), MAX_PATH);
    firefoxPath.ReleaseBuffer();
    if (m_bEnable)
    {
        if (::DeleteFile(firefoxPath))
        {
            Log(_T("Deleted Firefox browsing history: ") + firefoxPath, Clean);
        }
        else
        {
            CString msg;
            msg.Format(_T("Failed to delete Firefox history: %s (%u)"), firefoxPath, GetLastError());
            Log(msg, Error);
        }
    }
    else
    {
        Log(_T("Simulation: Would delete Firefox history: ") + firefoxPath, Clean);
    }
}

void CUSBOblivionDlg::ClearWifiHistory()
{
    Log(_T("Clearing Wi-Fi connection history..."));

    if (m_bEnable)
    {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
        {
            if (theApp.dyn_RegDeleteTreeW && theApp.dyn_RegDeleteTreeW(hKey, nullptr) == ERROR_SUCCESS)
            {
                Log(_T("Cleared Wi-Fi connection history from registry."), Clean);
            }
            else
            {
                CString msg;
                msg.Format(_T("Failed to clear Wi-Fi history (%u)"), GetLastError());
                Log(msg, Error);
            }
            RegCloseKey(hKey);
        }
        else
        {
            CString msg;
            msg.Format(_T("Failed to open Wi-Fi registry key (%u)"), GetLastError());
            Log(msg, Error);
        }
    }
    else
    {
        Log(_T("Simulation: Would clear Wi-Fi connection history."), Clean);
    }
}

void CUSBOblivionDlg::ClearRecentApps()
{
    Log(_T("Clearing recent apps history..."));

    CString recentPath;
    ExpandEnvironmentStrings(_T("%AppData%\\Microsoft\\Windows\\Recent"), recentPath.GetBuffer(MAX_PATH), MAX_PATH);
    recentPath.ReleaseBuffer();

    CFileFind ff;
    CString searchPath = recentPath + _T("\\*.*");
    BOOL bWorking = ff.FindFile(searchPath);
    while (bWorking)
    {
        bWorking = ff.FindNextFile();
        if (!ff.IsDirectory() && !ff.IsDots())
        {
            CString filePath = ff.GetFilePath();
            if (m_bEnable)
            {
                if (::DeleteFile(filePath))
                {
                    Log(_T("Deleted recent app: ") + filePath, Clean);
                }
                else
                {
                    CString msg;
                    msg.Format(_T("Failed to delete recent app: %s (%u)"), filePath, GetLastError());
                    Log(msg, Error);
                }
            }
            else
            {
                Log(_T("Simulation: Would delete recent app: ") + filePath, Clean);
            }
        }
    }
    ff.Close();

    static const LPCTSTR szRegistryKeys[] =
    {
        _T("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache"),
        _T("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags"),
        _T("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"),
        _T("Software\\Microsoft\\Windows\\Shell\\Bags"),
        _T("Software\\Microsoft\\Windows\\Shell\\BagMRU"),
        _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store"),
        _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Feristed"),
        _T("Software\\Microsoft\\Windows\\ShellNoRoam\\MuiCache"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
    };

    for (const auto& key : szRegistryKeys)
    {
        if (m_bEnable)
        {
            HKEY hKey;
            if (RegOpenKeyEx(HKEY_CURRENT_USER, key, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
            {
                if (theApp.dyn_RegDeleteTreeW && theApp.dyn_RegDeleteTreeW(hKey, nullptr) == ERROR_SUCCESS)
                {
                    Log(_T("Deleted registry key: HKCU\\") + CString(key), Clean);
                }
                else
                {
                    CString msg;
                    msg.Format(_T("Failed to delete registry key HKCU\\%s (%u)"), key, GetLastError());
                    Log(msg, Error);
                }
                RegCloseKey(hKey);
            }
        }
        else
        {
            Log(_T("Simulation: Would delete registry key HKCU\\") + CString(key), Clean);
        }
    }

    if (m_bEnable)
    {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\TypedPaths"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
        {
            RegDeleteValueFull(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\TypedPaths"), nullptr);
            RegCloseKey(hKey);
        }
    }
    else
    {
        Log(_T("Simulation: Would clear values in HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\TypedPaths"), Clean);
    }

    if (m_bEnable)
    {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunMRU"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
        {
            if (theApp.dyn_RegDeleteTreeW && theApp.dyn_RegDeleteTreeW(hKey, nullptr) == ERROR_SUCCESS)
            {
                Log(_T("Deleted registry key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunMRU"), Clean);
            }
            else
            {
                CString msg;
                msg.Format(_T("Failed to delete registry key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunMRU (%u)"), GetLastError());
                Log(msg, Error);
            }
            RegCloseKey(hKey);
        }
    }
    else
    {
        Log(_T("Simulation: Would delete registry key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunMRU"), Clean);
    }
}

// Hàm kiểm tra bản quyền
bool CUSBOblivionDlg::CheckLicense()
{
    CFile file;
    if (!file.Open(_T("license.dat"), CFile::modeRead | CFile::shareDenyWrite))
    {
        Log(_T("License file 'license.dat' not found."), Error);
        return false;
    }

    ULONGLONG fileLen = file.GetLength();
    if (fileLen < 2) // Ít nhất phải có 2 byte cho BOM
    {
        file.Close();
        Log(_T("License file 'license.dat' is empty or too small."), Error);
        return false;
    }

    // Đọc BOM UTF-16 LE (0xFF, 0xFE)
    BYTE bom[2];
    file.Read(bom, 2);
    if (bom[0] != 0xFF || bom[1] != 0xFE)
    {
        file.Close();
        Log(_T("License file does not have correct UTF-16 LE BOM."), Error);
        return false;
    }

    fileLen -= 2; // Bỏ qua BOM
    if (fileLen == 0)
    {
        file.Close();
        Log(_T("No data after BOM in license file."), Error);
        return false;
    }

    // Đọc toàn bộ dữ liệu dưới dạng wchar_t
    std::vector<wchar_t> buffer(fileLen / sizeof(wchar_t) + 1);
    file.Read(buffer.data(), (UINT)fileLen);
    buffer[fileLen / sizeof(wchar_t)] = 0; // Đảm bảo chuỗi kết thúc
    file.Close();

    CString encryptedData(buffer.data());
    if (encryptedData.IsEmpty())
    {
        Log(_T("Encrypted license data is empty."), Error);
        return false;
    }

    // Giải mã dữ liệu license (không log dữ liệu nhạy cảm)
    CString decryptedData = DecryptLicense(encryptedData);
    if (decryptedData.IsEmpty())
    {
        Log(_T("Failed to decrypt license data."), Error);
        return false;
    }

    // Dữ liệu theo định dạng: "license_key|uses_left|expiration_date"
    int pos1 = decryptedData.Find(_T("|"));
    int pos2 = decryptedData.Find(_T("|"), pos1 + 1);
    if (pos1 == -1 || pos2 == -1)
    {
        Log(_T("Invalid license data format."), Error);
        return false;
    }

    // Tách các thành phần, nhưng không log thông tin nhạy cảm
    // (chỉ lấy số lượt và expiration date để kiểm tra)
    CString usesLeftStr = decryptedData.Mid(pos1 + 1, pos2 - pos1 - 1);
    CString expirationDateStr = decryptedData.Mid(pos2 + 1);

    int usesLeft = _ttoi(usesLeftStr);
    time_t expirationDate = _ttoi64(expirationDateStr);
    time_t currentTime = time(nullptr);

    // Chuyển expirationDate sang định dạng ngày tháng (YYYY-MM-DD HH:MM:SS)
    wchar_t dateBuffer[100] = { 0 };
    tm localTime = { 0 };
    localtime_s(&localTime, &expirationDate);
    wcsftime(dateBuffer, 100, L"%Y-%m-%d %H:%M:%S", &localTime);
    CString expirationDateFormatted(dateBuffer);

    // Chỉ trả về true nếu số lượt sử dụng > 0 và thời gian hiện tại còn nhỏ hơn thời gian hết hạn
    if (usesLeft > 0 && currentTime < expirationDate)
    {
        CString msg;
        msg.Format(_T("License valid. Uses left: %d, Expiration date: %s"), usesLeft, expirationDateFormatted.GetString());
        Log(msg, Information);
        return true;
    }
    else
    {
        if (usesLeft <= 0)
            Log(_T("No uses left in license."), Error);
        if (currentTime >= expirationDate)
            Log(_T("License has expired."), Error);
        return false;
    }
}




bool CUSBOblivionDlg::UpdateLicenseUsage()
{
    // Mở file để đọc dữ liệu hiện tại
    CFile file;
    if (!file.Open(_T("license.dat"), CFile::modeRead | CFile::shareDenyWrite))
    {
        Log(_T("Failed to open license file for updating."), Error);
        return false;
    }

    ULONGLONG fileLen = file.GetLength();
    if (fileLen < 2)
    {
        file.Close();
        Log(_T("License file is empty or corrupted during update."), Error);
        return false;
    }

    // Đọc BOM
    BYTE bom[2];
    file.Read(bom, 2);
    if (bom[0] != 0xFF || bom[1] != 0xFE)
    {
        file.Close();
        Log(_T("License file does not have correct UTF-16 LE BOM during update."), Error);
        return false;
    }

    fileLen -= 2;
    if (fileLen == 0)
    {
        file.Close();
        Log(_T("No data after BOM in license file during update."), Error);
        return false;
    }

    std::vector<wchar_t> buffer(fileLen / sizeof(wchar_t) + 1);
    file.Read(buffer.data(), (UINT)fileLen);
    buffer[fileLen / sizeof(wchar_t)] = 0;
    file.Close();

    CString encryptedData(buffer.data());
    if (encryptedData.IsEmpty())
    {
        Log(_T("Encrypted license data is empty during update."), Error);
        return false;
    }

    CString decryptedData = DecryptLicense(encryptedData);
    if (decryptedData.IsEmpty())
    {
        Log(_T("Failed to decrypt license data during update."), Error);
        return false;
    }

    Log(_T("Decrypted license data during update: ") + decryptedData, Information);

    // Tách dữ liệu thành 3 phần: "license_key|uses_left|expiration_date"
    int pos1 = decryptedData.Find(_T("|"));
    int pos2 = decryptedData.Find(_T("|"), pos1 + 1);
    if (pos1 == -1 || pos2 == -1)
    {
        Log(_T("Invalid license data format during update."), Error);
        return false;
    }

    CString licenseKey = decryptedData.Left(pos1);
    CString usesLeftStr = decryptedData.Mid(pos1 + 1, pos2 - pos1 - 1);
    CString expirationDateStr = decryptedData.Mid(pos2 + 1);

    int usesLeft = _ttoi(usesLeftStr);
    usesLeft--; // Giảm số lượt sử dụng đi 1

    if (usesLeft < 0)
    {
        Log(_T("No uses left during update."), Error);
        return false;
    }

    CString newUsesLeftStr;
    newUsesLeftStr.Format(_T("%d"), usesLeft);

    Log(_T("License key: ") + licenseKey, Information);
    Log(_T("Uses left before update: ") + usesLeftStr, Information);
    Log(_T("Expiration date: ") + expirationDateStr, Information);
    Log(_T("New uses left: ") + newUsesLeftStr, Information);

    // Tạo chuỗi license mới theo mẫu: "license_key|uses_left|expiration_date"
    CString newLicenseData;
    newLicenseData.Format(_T("%s|%d|%s"), licenseKey.GetString(), usesLeft, expirationDateStr.GetString());
    Log(_T("New license data before encryption: ") + newLicenseData, Information);

    // Mã hóa dữ liệu license mới
    CString encryptedNewData = EncryptLicense(newLicenseData);

    // Log dữ liệu mã hóa dạng hex để kiểm tra
    CString hexData;
    for (int i = 0; i < encryptedNewData.GetLength(); i++)
    {
        CString temp;
        temp.Format(_T("\\x%04X"), (unsigned short)encryptedNewData[i]);
        hexData += temp;
    }
    Log(_T("New encrypted license data (hex): ") + hexData, Information);

    // Mở file để ghi đè toàn bộ nội dung (modeCreate sẽ tạo mới file)
    if (!file.Open(_T("license.dat"), CFile::modeCreate | CFile::modeWrite | CFile::shareDenyWrite))
    {
        Log(_T("Failed to open license file for writing during update."), Error);
        return false;
    }

    // Ghi BOM UTF-16 LE vào file
    BYTE newBOM[2] = { 0xFF, 0xFE };
    file.Write(newBOM, sizeof(newBOM));
    // Ghi dữ liệu mã hóa mới (số byte = số ký tự * sizeof(TCHAR))
    file.Write(encryptedNewData.GetBuffer(), encryptedNewData.GetLength() * sizeof(TCHAR));
    file.Close();

    Log(_T("License updated successfully. New uses left: ") + newUsesLeftStr, Information);
    return true;
}

//////////////////////////////////////////////////////////////////////////
// Hàm mã hóa XOR (đối xứng => dùng cho cả giải mã)
CString CUSBOblivionDlg::EncryptLicense(const CString& data)
{
    const TCHAR* key = _T("MySecretKey123");
    CString result = data;
    int keyLen = _tcslen(key);
    for (int i = 0; i < result.GetLength(); i++)
    {
        result.SetAt(i, result[i] ^ key[i % keyLen]);
    }
    return result;
}

//////////////////////////////////////////////////////////////////////////
// Hàm giải mã: do XOR đối xứng nên gọi lại EncryptLicense
CString CUSBOblivionDlg::DecryptLicense(const CString& data)
{
    return EncryptLicense(data);
}
