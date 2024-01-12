#include "StdAfx.h"

#include "dlg.h"
#include "resource.h"
#define MAXULONG 0xffffffff

extern const OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };

void DumpToken(HWND hwnd, HANDLE hToken);

void DumpObjectSecurity(HWND hwnd, HANDLE hObject);

void ShowXY(void (*fn)(HWND , HANDLE),HANDLE hObject, PCWSTR caption, HWND hwndParent, HFONT hFont);

int CustomMessageBox(HWND hWnd, PCWSTR lpText, PCWSTR lpszCaption, UINT uType)
{
	PCWSTR pszName = 0;

	switch (uType & MB_ICONMASK)
	{
	case MB_ICONINFORMATION:
		pszName = IDI_INFORMATION;
		break;
	case MB_ICONQUESTION:
		pszName = IDI_QUESTION;
		break;
	case MB_ICONWARNING:
		pszName = IDI_WARNING;
		break;
	case MB_ICONERROR:
		pszName = IDI_ERROR;
		break;
	}

	MSGBOXPARAMS mbp = {
		sizeof(mbp),
		hWnd,
		(HINSTANCE)&__ImageBase,
		lpText, 
		lpszCaption, 
		(uType & ~MB_ICONMASK)|MB_USERICON,
		MAKEINTRESOURCE(1)
	};

	return MessageBoxIndirect(&mbp);
}

int ShowErrorBox(HWND hWnd, PCWSTR lpCaption, HRESULT dwError, UINT uType)
{
	int r = 0;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = CustomMessageBox(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

NTSTATUS GetProcessList(_Out_ SYSTEM_PROCESS_INFORMATION** ppspi);
NTSTATUS GetSystemToken(PSYSTEM_PROCESS_INFORMATION pspi, PHANDLE phSysToken);
NTSTATUS ImpersonateSystemToken();
NTSTATUS RtlRevertToSelf();

enum THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition
};

class YTd : public ZDlg
{
	HICON _M_hico[2] = {};
	HANDLE _M_hSysToken = 0;
	HFONT _M_hfont = 0;
	HFONT _M_hfontB = 0;
	ULONG _M_pid = 0, _M_tid = 0;

	CHAR Is32Bit(ULONG NumberOfThreads, SYSTEM_EXTENDED_THREAD_INFORMATION* TH)
	{
		if (!NumberOfThreads)
		{
			return ' ';
		}
		do 
		{
			if (MAXULONG < (ULONG_PTR)TH->Win32StartAddress || 
				MAXULONG < (ULONG_PTR)TH->TebBase)
			{
				return ' ';
			}

		} while (TH++, --NumberOfThreads);

		return '*';
	}

	void EnumT(HWND hwndCB, SYSTEM_PROCESS_INFORMATION* pspi, HANDLE UniqueProcessId)
	{
		ULONG NextEntryOffset = 0;

		do 
		{
			(ULONG_PTR&)pspi += NextEntryOffset;

			if (pspi->UniqueProcessId == UniqueProcessId)
			{
				if (ULONG NumberOfThreads = pspi->NumberOfThreads)
				{
					SYSTEM_EXTENDED_THREAD_INFORMATION* TH = pspi->Threads;
					do 
					{
						WCHAR sz[0x400];
						PVOID StartAddress = TH->Win32StartAddress;
						if (!StartAddress)
						{
							StartAddress = TH->StartAddress;
						}

						static const PCSTR WR[] = {
							"Executive",
							"FreePage",
							"PageIn",
							"PoolAllocation",
							"DelayExecution",
							"Suspended",
							"UserRequest",
							"WrExecutive",
							"WrFreePage",
							"WrPageIn",
							"WrPoolAllocation",
							"WrDelayExecution",
							"WrSuspended",
							"WrUserRequest",
							"WrSpare0",
							"WrQueue",
							"WrLpcReceive",
							"WrLpcReply",
							"WrVirtualMemory",
							"WrPageOut",
							"WrRendezvous",
							"WrKeyedEvent",
							"WrTerminated",
							"WrProcessInSwap",
							"WrCpuRateControl",
							"WrCalloutStack",
							"WrKernel",
							"WrResource",
							"WrPushLock",
							"WrMutex",
							"WrQuantumEnd",
							"WrDispatchInt",
							"WrPreempted",
							"WrYieldExecution",
							"WrFastMutex",
							"WrGuardedMutex",
							"WrRundown",
							"WrAlertByThreadId",
							"WrDeferredPreempt",
							"WrPhysicalFault",
							"WrIoRing",
							"WrMdlCache",
						};

						char szwr[16];
						PCSTR pwr;
						switch (TH->ThreadState)
						{
						case StateWait:
							if (TH->WaitReason < _countof(WR))
							{
								pwr = WR[TH->WaitReason];
							}
							else
							{
								sprintf_s(szwr, _countof(szwr), "<%x>", TH->WaitReason);
								pwr = szwr;
							}
							break;
						case StateInitialized:
							pwr = "Initialized";
							break;
						case StateReady:
							pwr = "Ready";
							break;
						case StateRunning:
							pwr = "Running";
							break;
						case StateStandby:
							pwr = "Standby";
							break;
						case StateTerminated:
							pwr = "Terminated";
							break;
						case StateTransition:
							pwr = "Transition";
							break;
						default:
							sprintf_s(szwr, _countof(szwr), ")%x(", TH->ThreadState);
							pwr = szwr;
						}

						swprintf_s(sz, _countof(sz), L"%5x %p %p %S", 
							(ULONG)(ULONG_PTR)TH->ClientId.UniqueThread,
							StartAddress, TH->TebBase, pwr);

						int i = ComboBox_AddString(hwndCB, sz);
						
						if (0 <= i)
						{
							ComboBox_SetItemData(hwndCB, i, TH->ClientId.UniqueThread);
						}

					} while (TH++, --NumberOfThreads);
				}

				return ;
			}

		} while (NextEntryOffset = pspi->NextEntryOffset);
	}

	void EnumT(HWND hwndDlg)
	{
		EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON2), FALSE);
		_M_tid = 0;
		HWND hwndCB = GetDlgItem(hwndDlg, IDC_COMBO1);
		ComboBox_ResetContent(hwndDlg = GetDlgItem(hwndDlg, IDC_COMBO2));
		int i = ComboBox_GetCurSel(hwndCB);
		if (0 > i)
		{
			return ;
		}

		if (ULONG_PTR UniqueProcessId = ComboBox_GetItemData(hwndCB, i))
		{
			SYSTEM_PROCESS_INFORMATION* pspi;
			if (0 <= GetProcessList(&pspi))
			{
				EnumT(hwndDlg, pspi, (HANDLE)UniqueProcessId);
				LocalFree(pspi);
			}
		}
	}

	void EnumP(HWND hwndCB, SYSTEM_PROCESS_INFORMATION* pspi)
	{
		ULONG NextEntryOffset = 0;

		do 
		{
			(ULONG_PTR&)pspi += NextEntryOffset;

			if (pspi->UniqueProcessId)
			{
				WCHAR sz[0x400];
				swprintf_s(sz, _countof(sz), L"%5x(%5x) %2u %c %3u [%4u] %wZ", 
					(ULONG)(ULONG_PTR)pspi->UniqueProcessId,
					(ULONG)(ULONG_PTR)pspi->InheritedFromUniqueProcessId, 
					pspi->SessionId,
					Is32Bit(pspi->NumberOfThreads, pspi->Threads),
					pspi->NumberOfThreads,
					pspi->HandleCount,
					pspi->ImageName);

				int i = ComboBox_AddString(hwndCB, sz);
				if (0 <= i)
				{
					ComboBox_SetItemData(hwndCB, i, pspi->UniqueProcessId);
				}
			}

		} while (NextEntryOffset = pspi->NextEntryOffset);
	}

	void EnumP(HWND hwndDlg)
	{
		EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON1), FALSE);
		EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON2), FALSE);
		_M_pid = 0, _M_tid = 0;

		ComboBox_ResetContent(GetDlgItem(hwndDlg, IDC_COMBO2));
		ComboBox_ResetContent(hwndDlg = GetDlgItem(hwndDlg, IDC_COMBO1));

		SYSTEM_PROCESS_INFORMATION* pspi;
		if (0 <= GetProcessList(&pspi))
		{
			if (!_M_hSysToken)
			{
				GetSystemToken(pspi, &_M_hSysToken);
			}
			EnumP(hwndDlg, pspi);
			LocalFree(pspi);
		}
	}

	void OnInitDialog(HWND hwndDlg)
	{
		HICON hico;
		if (S_OK == LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1), 
			GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hico))
		{
			SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hico);
			_M_hico[0] = hico;
		}

		if (S_OK == LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1), 
			GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), &hico))
		{
			SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)hico);
			_M_hico[1] = hico;
		}

		NONCLIENTMETRICS ncm = { sizeof(ncm) };
		if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
		{
			ncm.lfMenuFont.lfQuality = CLEARTYPE_QUALITY;
			ncm.lfMenuFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
			ncm.lfMenuFont.lfWeight = FW_NORMAL;
			wcscpy(ncm.lfMenuFont.lfFaceName, L"Courier New");

			if (HFONT hfont = CreateFontIndirectW(&ncm.lfMenuFont))
			{
				_M_hfont = hfont;
				SendDlgItemMessageW(hwndDlg, IDC_COMBO1, WM_SETFONT, (WPARAM)hfont, 0);
				SendDlgItemMessageW(hwndDlg, IDC_COMBO2, WM_SETFONT, (WPARAM)hfont, 0);
			}

			ncm.lfMenuFont.lfHeight = -ncm.iMenuHeight;

			if (HFONT hfont = CreateFontIndirectW(&ncm.lfMenuFont))
			{
				_M_hfontB = hfont;
			}
		}
	}

	void OnDestroy()
	{
		HICON hico;

		if (_M_hSysToken)
		{
			NtClose(_M_hSysToken);
		}

		if (_M_hfontB)
		{
			DeleteObject(_M_hfontB);
		}

		if (_M_hfont)
		{
			DeleteObject(_M_hfont);
		}

		if (hico = _M_hico[1])
		{
			DestroyIcon(hico);
		}

		if (hico = _M_hico[0])
		{
			DestroyIcon(hico);
		}
	}

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		int i;

		switch (uMsg)
		{
		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				return 0;

			case MAKEWPARAM(IDC_COMBO1, CBN_DROPDOWN):
				EnumP(hwndDlg);
				break;

			case MAKEWPARAM(IDC_COMBO2, CBN_DROPDOWN):
				EnumT(hwndDlg);
				break;

			case MAKEWPARAM(IDC_COMBO1, CBN_SELCHANGE ):
				if (0 <= (i = ComboBox_GetCurSel((HWND)lParam)))
				{
					if (_M_pid = (ULONG)ComboBox_GetItemData((HWND)lParam, i))
					{
						EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON1), TRUE);
					}
				}
				break;
			case MAKEWPARAM(IDC_COMBO2, CBN_SELCHANGE ):
				if (0 <= (i = ComboBox_GetCurSel((HWND)lParam)))
				{
					if (_M_tid = (ULONG)ComboBox_GetItemData((HWND)lParam, i))
					{
						EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON2), TRUE);
					}
				}
				break;

			case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
				if (_M_pid)
				{
					ShowPT(hwndDlg, (ULONG_PTR)_M_pid);
				}
				break;

			case MAKEWPARAM(IDC_BUTTON2, BN_CLICKED):
				if (_M_tid)
				{
					ShowTT(hwndDlg, (ULONG_PTR)_M_tid);
				}
				break;
			}
			break;

		case WM_INITDIALOG:
			OnInitDialog(hwndDlg);
			break;

		case WM_DESTROY:
			OnDestroy();
			break;
		}

		return __super::DialogProc(hwndDlg, uMsg, wParam, lParam);
	}

	void ShowPT(HWND hwndDlg, ULONG pid)
	{
		HANDLE hProcess, hToken;
		CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid };
		WCHAR sz[32];
		swprintf_s(sz, _countof(sz), L"[%x] process", pid);

		NTSTATUS status;

		BOOL bRevert = FALSE;

		if (_M_hSysToken)
		{
			NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &_M_hSysToken, sizeof(_M_hSysToken));
		}

		if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, const_cast<OBJECT_ATTRIBUTES*>(&zoa), &cid)))
		{
			status = NtOpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_QUERY_SOURCE|READ_CONTROL, &hToken);
			NtClose(hProcess);
			if (0 <= status)
			{
				ShowXY(DumpToken, hToken, sz, hwndDlg, _M_hfontB);
				NtClose(hToken);
			}
		}

		if (bRevert)
		{
			RtlRevertToSelf();
		}

		if (0 > status)
		{
			ShowErrorBox(hwndDlg, sz, HRESULT_FROM_NT(status), MB_ICONHAND);
		}
	}

	void ShowTT(HWND hwndDlg, ULONG tid)
	{
		HANDLE hThread, hToken;
		CLIENT_ID cid = { 0, (HANDLE)(ULONG_PTR)tid };
		WCHAR sz[32];
		swprintf_s(sz, _countof(sz), L"[%x] thread", tid);

		NTSTATUS status;

		BOOL bRevert = FALSE;

		if (_M_hSysToken)
		{
			NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &_M_hSysToken, sizeof(_M_hSysToken));
		}

		if (0 <= (status = NtOpenThread(&hThread, THREAD_QUERY_LIMITED_INFORMATION, const_cast<OBJECT_ATTRIBUTES*>(&zoa), &cid)))
		{
			status = NtOpenThreadToken(hThread, TOKEN_QUERY|TOKEN_QUERY_SOURCE|READ_CONTROL, FALSE, &hToken);
			NtClose(hThread);
			if (0 <= status)
			{
				ShowXY(DumpToken, hToken, sz, hwndDlg, _M_hfontB);
				NtClose(hToken);
			}
		}

		if (bRevert)
		{
			RtlRevertToSelf();
		}

		if (0 > status)
		{
			ShowErrorBox(hwndDlg, sz, HRESULT_FROM_NT(status), MB_ICONHAND);
		}
	}
};

void NTAPI ep(void* )
{
	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);
	{
		YTd dlg;
		dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG1), 0, 0);
	}

	ExitProcess(0);
}