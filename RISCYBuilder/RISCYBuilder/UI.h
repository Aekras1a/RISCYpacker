#pragma once
#include <Windows.h>
#include "Settings.h"
#include <string>

using namespace std;

class UI
{
public:
	static Settings Run();
	static void ErrorMsg(wstring msg);
	static void SuccessMsg(wstring msg);
private:
	static void PrintBanner();
	static wstring PromptHollowPath();
	static wstring PromptPackPath();
	static int PromptPackLocation();
	static string PromptResourceName();
	static HANDLE hConsole;
};

