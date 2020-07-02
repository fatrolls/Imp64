#include "RLString.h"

CRLString::CRLString(void)
{
	string = new char[1];
	string[0] = 0;
}

CRLString::~CRLString(void)
{
	delete[] string;
}

//copy constructor!!!
CRLString::CRLString(const CRLString& s)
{
	size_t temp_len = strlen(s.string) + 1;
	string = new char[temp_len];
	strcpy(string, s.string);

}


CRLString::CRLString(const char *str)
{
	size_t len = strlen(str) + 1;
	string = new char[len];
	strcpy(string, str);

}

const char *CRLString::GetString()
{
	return string;
}

char *CRLString::SetSize(size_t size)
{
	delete[] string;
	string = new char[size];
	memset(string, 0, size);
	return string;
}

void CRLString::MakeUpper()
{
	size_t i;
	size_t size = strlen(string);
	for (i = 0; i < size; i++)
		if (string[i] >= 'a' && string[i] <= 'z')
			string[i] -= 'a' - 'A';
}

void CRLString::MakeLower()
{
	size_t i;
	size_t size = strlen(string);
	for (i = 0; i < size; i++)
		if (string[i] >= 'A' && string[i] <= 'Z')
			string[i] += 'a' - 'A';
}


CRLString::operator LPCSTR() const
{
	return string;
}

CRLString::operator LPSTR() const
{
	return string;
}


BOOL CRLString::operator==(const CRLString &s1) const
{
	return (BOOL)!(strcmp(string, s1.string));
}

CRLString &CRLString::operator=(const CRLString &s1)
{
	delete[] string;
	size_t temp_size = strlen(s1.string) + 1;
	string = new char[temp_size];
	strcpy(string, s1.string);
	return *this;
}

CRLString &CRLString::operator=(const LPCSTR str1)
{
	delete[] string;
	size_t temp_size = strlen(str1) + 1;
	string = new char[temp_size];
	strcpy(string, str1);
	return *this;
}


CRLString operator+(LPCSTR str, const CRLString &s1)
{
	size_t temp_len = strlen(str) + strlen(s1.string) + 1;
	char *temp_str = new char[temp_len];
	strcpy(temp_str, str);
	strcpy(temp_str+strlen(str), s1.string);
	CRLString blah(temp_str);
	delete[] temp_str;
	return blah;
}

CRLString &CRLString::operator+=(const CRLString &s1)
{
	size_t temp_size = strlen(string) + strlen(s1.string) + 1;
	char *temp_str = new char[temp_size];
	strcpy(temp_str, string);
	strcpy(temp_str+strlen(string), s1.string);
	delete[] string;

	string = temp_str;
	
	return *this;

}

