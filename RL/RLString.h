#pragma once
#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <windows.h>
class CRLString
{
public:
	CRLString(void);
	CRLString(const char *str);
	CRLString(const CRLString& s);
	virtual ~CRLString(void);
	const char *GetString();
	char *SetSize(size_t size);
	void MakeUpper();
	void MakeLower();

	operator LPCSTR() const;
	operator LPSTR() const;
	BOOL CRLString::operator==(const CRLString &s1) const;
	CRLString & CRLString::operator=(const CRLString &s1);
	CRLString & CRLString::operator=(const LPCSTR str1);
	CRLString & CRLString::operator+=(const CRLString &s);
	friend CRLString operator+(LPCSTR str, const CRLString &s1);

private:
	char *string;
};

