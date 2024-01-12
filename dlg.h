#pragma once

class __declspec(novtable) ZObject
{
private:

	LONG _dwRef;

protected:

	virtual ~ZObject()
	{
	}

public:

	ZObject()
	{
		_dwRef = 1;
	}

	ULONG AddRef()
	{
		return InterlockedIncrementNoFence(&_dwRef);
	}

	ULONG Release()
	{
		if (ULONG dwRef = InterlockedDecrement(&_dwRef)) 
		{
			return dwRef;
		}
		delete this;
		return 0;
	}
};

class __declspec(novtable) ZDlg : public ZObject
{
	HWND _hWnd = 0;
	LONG _dwCallCount;

	INT_PTR WrapperDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static INT_PTR CALLBACK _DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

	INT_PTR MStartDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static INT_PTR CALLBACK StartDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

protected:
	virtual void AfterLastMessage()
	{
	}

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

public:

	HWND Create(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, LPARAM dwInitParam);

	INT_PTR DoModal(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, LPARAM dwInitParam);

	HWND getHWND(){ return _hWnd; }
};