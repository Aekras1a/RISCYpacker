#include "stdafx.h"
#include "UI.h"
#include <iostream>
#include <Shlwapi.h>

HANDLE UI::hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
static string VERSION = "1.1";

#define BLACK			0
#define BLUE			1
#define GREEN			2
#define CYAN			3
#define RED				4
#define MAGENTA			5
#define BROWN			6
#define LIGHTGRAY		7
#define DARKGRAY		8
#define LIGHTBLUE		9
#define LIGHTGREEN		10
#define LIGHTCYAN		11
#define LIGHTRED		12
#define LIGHTMAGENTA	13
#define YELLOW			14
#define WHITE			15

void UI::SuccessMsg(wstring msg)
{
	SetConsoleTextAttribute(hConsole, LIGHTGREEN);
	wcout << endl << msg << endl<<endl;
}

void UI::PrintBanner()
{
	SetConsoleTextAttribute(hConsole, LIGHTGREEN);
	cout << "\t______ _____ _____ _____      ______          _             "
		"\n\t| ___ \\_   _/  ___/  __ \\     | ___ \\        | |            "
		"\n\t| |_/ / | | \\ `--.| /  \\/_   _| |_/ /_ _  ___| | _____ _ __ "
		"\n\t|    /  | |  `--. \\ |   | | | |  __/ _` |/ __| |/ / _ \\ '__|"
		"\n\t| |\\ \\ _| |_/\\__/ / \\__/\\ |_| | | | (_| | (__|   <  __/ |   "
		"\n\t\\_| \\_|\\___/\\____/ \\____/\\__, \\_|  \\__,_|\\___|_|\\_\\___|_|   "
		"\n\t                          __/ |                             "
		"\n\t                         |___/                             ";

	SetConsoleTextAttribute(hConsole, RED);
	cout << endl << endl << "RISCyPacker (v"<< VERSION <<") - Process Hollowing PE Packer." << endl << endl;
}

wstring UI::PromptPackPath()
{
	wchar_t path[MAX_PATH];
	SetConsoleTextAttribute(hConsole, YELLOW);
	cout << endl;
	SetConsoleTextAttribute(hConsole, LIGHTGREEN);
	cout << "[Path to Executable]>";
	SetConsoleTextAttribute(hConsole, YELLOW);
	wcin.getline(path, MAX_PATH);
	return path;
}

int UI::PromptPackLocation()
{
	int option;
	SetConsoleTextAttribute(hConsole, YELLOW);
	cout << endl;
	SetConsoleTextAttribute(hConsole, LIGHTGREEN);
	cout << "1 - Pack as Resource" << endl;
	cout << "2 - Pack as Section [Not Supported]" << endl;
	cout << "3 - Append packed data to PE [Not Supported]" << endl <<  endl;
	SetConsoleTextAttribute(hConsole, YELLOW);
	cout << "[Pack Location (" << PackLocation::Resource << "-"<< PackLocation::Appended <<")]>";
	cin >> option;
	
	///TODO: add support for other pack options
	return option;
}

void UI::ErrorMsg(wstring msg)
{
	
	SetConsoleTextAttribute(hConsole, LIGHTRED);
	wcout << msg << endl;
	SetConsoleTextAttribute(hConsole, YELLOW);
}

wstring UI::PromptHollowPath()
{
	wchar_t path[MAX_PATH];
	SetConsoleTextAttribute(hConsole, YELLOW);
	cout << endl;
	cout << "Specify fullpath to Exe to hollow (MUST EXIST ON TARGET MACHINE)" << endl;
	cout << endl;
	SetConsoleTextAttribute(hConsole, LIGHTGREEN);
	cout << "[Path to Executable]>";
	SetConsoleTextAttribute(hConsole, YELLOW);
	wcin.getline(path, MAX_PATH);
	return path;
}

string UI::PromptResourceName()
{
	string name;

	SetConsoleTextAttribute(hConsole, YELLOW);
	cout << endl;
	cout << "Name of resource to unpack into" << endl;
		UI::ErrorMsg(L"NOT SUPPORTED. LEAVE BLANK");
	cout<< endl << endl;
	SetConsoleTextAttribute(hConsole, LIGHTGREEN);
	cout << "[Name of Resource]>";
	SetConsoleTextAttribute(hConsole, YELLOW);
	cin.clear();
	cin.ignore(1000, '\n');
	while (name.empty())
		name = cin.get();

	if (name == "\n")
		name = "DATA";

	return name;
}

Settings UI::Run()
{
	Settings settings;
	PrintBanner();
	bool success = true;
	do {
		success = true;
		settings.exePackPath = PromptPackPath();
		HANDLE hFile = CreateFile(settings.exePackPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			UI::ErrorMsg(L"File either does not exist or cannot be open");
			success = false;
		}
		else {
			CloseHandle(hFile);
		}
	} while (!success);
	
	do {
		success = true;
		settings.packLocation = PromptPackLocation();
		if (settings.packLocation != PackLocation::Resource) {
			UI::ErrorMsg(L"Option not supported!");
			success = false;
		}
	} while (!success);

	if (settings.packLocation == PackLocation::Resource)
		settings.resourceName = PromptResourceName();
	
	settings.exeHollowPath = PromptHollowPath();
	return settings;
}
