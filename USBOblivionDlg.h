// USBOblivionDlg.h
#pragma once

#include "CtrlsResize.h"
#include <ctime>

using CKeyType = enum
{
    mControlSet_Key,
    mControlSet_Val,
    mHKLM_Key,
    mHKLM_Val,
    mHKCU_Key,
    mHKCU_Val,
    mHKCR_Key,
    mHKCR_Val
};

using CKeyDef = struct
{
    CKeyType    nMode;
    LPCTSTR     szKeyName;
    LPCTSTR     szKeySubstring;
    LPCTSTR     szValueName;
    LPCTSTR     szValueSubstring;
    BOOL        bDeleteEmpty;
};

template < class T1, class T2 >
class C2
{
public:
    inline C2() noexcept = default;
    inline C2(const T1& f, const T2& s) noexcept : first(f), second(s) {}
    T1 first;
    T2 second;
};

using CStringC2 = C2 < CString, CString >;
using CStringC2List = CList < CStringC2 >;

class CUSBOblivionDlg : public CDialog
{
public:
    CUSBOblivionDlg(CWnd* pParent = nullptr) noexcept;
    virtual ~CUSBOblivionDlg();

    enum { IDD = IDD_USBOBLIVION_DIALOG };

    BOOL        m_bEnable;
    BOOL        m_bAuto;
    BOOL        m_bSave;
    CString     m_sSave;
    CString     m_sLog;
    BOOL        m_bRestorePoint;
    BOOL        m_bReboot;
    BOOL        m_bCloseExplorer;
    BOOL        m_bSilent;
    BOOL        m_bElevation;

    BOOL        m_bClearBrowser;
    BOOL        m_bClearWifi;
    BOOL        m_bClearApps;

    INT_PTR DoModal() override;

protected:
    CImageList  m_oImages;
    HICON       m_hIcon;
    CListCtrl   m_pReport;
    int         m_nSelected;
    CStdioFile  m_oFile;
    CCtrlResize m_CtrlsResize;
    CRect       m_InitialRect;
    DWORD       m_nDrives;

    CString     m_sDeleteKeyString;
    CString     m_sDeleteValueString;

    using CLogItem = C2< CString, UINT >;
    using CLogList = CList< CLogItem* >;
    cs                      m_pSection;
    CAutoPtr< CLogList >    m_pReportList;
    bool                    m_bRunning;

    enum { Information = 0, Warning, Error, Search, Done, Clean, Regedit, Lock, Eject };

    void Log(const CString& sText, UINT nType = Information);
    void Log(UINT nID, UINT nType = Information);

    static CString GetKeyName(HKEY hRoot);
    LSTATUS RegOpenKeyFull(HKEY hKey, LPCTSTR lpSubKey, REGSAM samDesired, PHKEY phkResult);
    LSTATUS RegDeleteKeyFull(HKEY hKey, const CString& sSubKey);
    LSTATUS RegDeleteValueFull(HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValue);

    void ProcessKey(HKEY hRoot, const CString& sRoot, const CKeyDef& def, CStringList& oKeys);
    void ProcessValue(HKEY hRoot, const CString& sRoot, const CKeyDef& def, CStringC2List& oValues);

    bool PrepareBackup();
    void FinishBackup();
    void Write(const CString& sText);
    void SaveKey(HKEY hRoot, LPCTSTR szKeyName, LPCTSTR szValueName = nullptr);
    void SaveValue(LPCTSTR szName, DWORD dwType, LPBYTE pData, DWORD dwSize);

    BOOL RunAsSystem();
    BOOL RunAsProcess(DWORD dwProcessID);
    void Run();

    void StopServices();
    bool EjectDrive(TCHAR DriveLetter);
    void EjectDrives();
    void CloseExplorer();
    void StartExplorer();
    void CleanFiles();
    void CleanLogs();
    void CleanLocalMachine();
    void CleanMountedDevices();
    void CleanWindowsSearch();
    void CleanUsers();
    void Reboot();

    void DoDeleteFile(LPCTSTR szPath);
    void DoDeleteLog(LPCTSTR szName);
    void DeleteKey(HKEY hRoot, const CString& sSubKey);
    void DeleteValue(HKEY hRoot, LPCTSTR szSubKey, LPCTSTR szValue);
    void CopyToClipboard(const CString& sData);

    // Hàm bản quyền
    bool CheckLicense();              // Kiểm tra file license.dat
    CString EncryptLicense(const CString& data);  // Mã hóa dữ liệu
    CString DecryptLicense(const CString& data);  // Giải mã dữ liệu
    bool UpdateLicenseUsage();        // Cập nhật số lần sử dụng

    void ClearBrowserHistory();
    void ClearWifiHistory();
    void ClearRecentApps();

    void DoDataExchange(CDataExchange* pDX) override;
    BOOL OnInitDialog() override;
    void OnOK() override;
    void OnCancel() override;

    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
    afx_msg void OnDestroy();
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    afx_msg void OnNMRClickReport(NMHDR* pNMHDR, LRESULT* pResult);
    afx_msg void OnCopy();
    afx_msg void OnCopyAll();
    afx_msg BOOL OnHelpInfo(HELPINFO* pHelpInfo);
    afx_msg BOOL OnDeviceChange(UINT nEventType, DWORD_PTR dwData);
    afx_msg void OnTimer(UINT_PTR nIDEvent);
    afx_msg void OnBnClickedEnable();

    DECLARE_MESSAGE_MAP()

    THREAD(CUSBOblivionDlg, RunThread)
};