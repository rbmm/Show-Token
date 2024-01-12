#include "StdAfx.h"

#include "dlg.h"
#include "../inc/rtlframe.h"

struct FC 
{
	PVOID ctx;
};

INT_PTR ZDlg::MStartDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	SetWindowLongPtr(hwndDlg, DWLP_USER, (LONG_PTR)this);
	SetWindowLongPtr(hwndDlg, DWLP_DLGPROC, (LONG_PTR)_DialogProc);
	AddRef();
	_dwCallCount = 1 << 31;
	_hWnd = hwndDlg;
	return WrapperDialogProc(hwndDlg, uMsg, wParam, lParam);
}

INT_PTR CALLBACK ZDlg::StartDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (FC* pf = RTL_FRAME<FC>::get())
	{
		return reinterpret_cast<ZDlg*>(pf->ctx)->MStartDialogProc(hwndDlg, uMsg, wParam, lParam);
	}
	return 0;
}

INT_PTR ZDlg::WrapperDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	_dwCallCount++;
	lParam = DialogProc(hwndDlg, uMsg, wParam, lParam);
	if (!--_dwCallCount)
	{
		_hWnd = 0;
		AfterLastMessage();
		Release();
	}
	return lParam;
}

INT_PTR CALLBACK ZDlg::_DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return reinterpret_cast<ZDlg*>(GetWindowLongPtrW(hwndDlg, DWLP_USER))->WrapperDialogProc(hwndDlg, uMsg, wParam, lParam);
}

INT_PTR ZDlg::DialogProc(HWND /*hwndDlg*/, UINT uMsg, WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	switch (uMsg)
	{
	case WM_NCDESTROY:
		_bittestandreset(&_dwCallCount, 31);
		break;
	}

	return 0;
}

HWND ZDlg::Create(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent, LPARAM dwInitParam)
{
	RTL_FRAME<FC> f;
	f.ctx = this;
	return CreateDialogParam(hInstance, lpTemplateName, hWndParent, StartDialogProc, dwInitParam);
}

INT_PTR ZDlg::DoModal(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent, LPARAM dwInitParam)
{
	RTL_FRAME<FC> f;
	f.ctx = this;
	return DialogBoxParam(hInstance, lpTemplateName, hWndParent, StartDialogProc, dwInitParam);
}