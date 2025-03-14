//
// cs.h
//
// Copyright (c) Nikolay Raspopov, 2009-2023.
// This file is part of USB Oblivion (https://www.cherubicsoft.com/en/projects/usboblivion/)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//

#pragma once

namespace c4u {

inline DWORD WaitForMultipleObjectsLoop (
	const DWORD nCount,
	const HANDLE* const pHandles,
	const BOOL fWaitAll,
	const DWORD dwMilliseconds) noexcept
{
    MSG msg;
	DWORD res;
	do {
		while (PeekMessage (&msg, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage (&msg);
			DispatchMessage (&msg);
		}
		res = MsgWaitForMultipleObjects (nCount, pHandles, fWaitAll, dwMilliseconds, QS_ALLINPUT);
	} while (res == WAIT_OBJECT_0 + nCount);
	return res;
}

inline DWORD CoWaitForSingleObject (HANDLE Handle, const DWORD dwMilliseconds) noexcept
{
	return WaitForMultipleObjectsLoop (1, &Handle, FALSE, dwMilliseconds);
}

/*inline DWORD CoWaitForSingleObject (
									HANDLE Handle,
									DWORD dwMilliseconds)
{
	DWORD index = 0;
	switch (CoWaitForMultipleHandles (0, dwMilliseconds, 1, &Handle, &index)) {
		case S_OK:
			return WAIT_OBJECT_0;
		case RPC_S_CALLPENDING:
			return WAIT_TIMEOUT;
	}
	return WAIT_ABANDONED;
}*/

inline DWORD CoWaitForMultipleObjects (
									   const DWORD nCount,
									   const HANDLE* const lpHandles,
									   const BOOL bWaitAll,
									   const DWORD dwMilliseconds) noexcept
{
	return WaitForMultipleObjectsLoop (nCount, lpHandles, bWaitAll, dwMilliseconds);
}

/*inline DWORD CoWaitForMultipleObjects (
									   DWORD nCount,
									   const HANDLE* lpHandles,
									   BOOL bWaitAll,
									   DWORD dwMilliseconds)
{
	DWORD index = 0;
	switch (CoWaitForMultipleHandles (bWaitAll ? COWAIT_WAITALL : 0,
		dwMilliseconds, nCount, const_cast <HANDLE*>(lpHandles), &index)) {
	case S_OK:
		return index + WAIT_OBJECT_0;
	case RPC_S_CALLPENDING:
		return WAIT_TIMEOUT;
	}
	return index + WAIT_ABANDONED;
}*/

class locker
{
public:
	virtual void lock () const = 0;
	virtual void unlock () const = 0;
	virtual bool try_lock (const DWORD timeout /* ��, 0 ��� INFINITE */) const = 0;
};

class mutex : public locker
{
public:
	inline mutex () noexcept
	{
		m_mutex = CreateMutex (nullptr, false, nullptr);
	}

	inline ~mutex () noexcept
	{
		CloseHandle (m_mutex);
	}

	virtual void lock () const noexcept override
	{
		CoWaitForSingleObject (m_mutex, INFINITE);
	}

	virtual void unlock () const noexcept override
	{
		ReleaseMutex (m_mutex);
	}

	virtual bool try_lock (const DWORD timeout /* ��, 0 ��� INFINITE */) const noexcept override
	{
		return (WaitForMultipleObjectsLoop (1, const_cast <const HANDLE*> (&m_mutex),
			FALSE, timeout) == WAIT_OBJECT_0);
	}

protected:
	mutable HANDLE m_mutex;

private:
	mutex( const mutex& );
	mutex& operator = ( const mutex& );
};

class cs : public locker
{
public:
	inline cs () noexcept
	{
		InitializeCriticalSection  (&m_sect);
	}

	inline ~cs () noexcept
	{
		DeleteCriticalSection (&m_sect);
	}

	virtual void lock () const noexcept override
	{
		EnterCriticalSection (&m_sect);
	}

	virtual void unlock () const noexcept override
	{
		LeaveCriticalSection (&m_sect);
	}

	virtual bool try_lock (const DWORD timeout /* ��, 0 ��� INFINITE */) const noexcept override
	{
		DWORD start_time = GetTickCount ();
		do {
			if (TryEnterCriticalSection (&m_sect))
				return true;
			MSG msg;
			while (PeekMessage (&msg, nullptr, 0, 0, PM_REMOVE)) {
				TranslateMessage (&msg);
				DispatchMessage (&msg);
			}
		} while (GetTickCount () - start_time < timeout);
		return false;
	}

protected:
	mutable CRITICAL_SECTION m_sect;

private:
	cs( const cs& );
	cs& operator = ( const cs& );
};

class locker_holder
{
public:
	inline locker_holder (const locker* c) noexcept
	{
		if (c) {
			c->lock ();
			m_hold = c;
		}
	}

	inline locker_holder (const locker* c, const DWORD timeout /* ��, 0 ��� INFINITE */) noexcept
	{
		if (c && c->try_lock (timeout)) {
			m_hold = c;
		} else
			m_hold = nullptr;
	}

	inline operator bool () const noexcept
	{
		return (m_hold != nullptr);
	}

	inline ~locker_holder () noexcept
	{
		if (m_hold) {
			m_hold->unlock ();
			m_hold = nullptr;
		}
	}
protected:
	const locker* m_hold;

private:
	locker_holder( const locker_holder& );
	locker_holder& operator = ( const locker_holder& );
};

}
