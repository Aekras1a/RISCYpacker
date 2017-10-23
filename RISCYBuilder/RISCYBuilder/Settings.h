#pragma once
#include <Windows.h>
#include <string>

enum PackLocation {
	Resource = 1,
	Section = 2,
	Appended = 3
};

struct Settings {
	std::wstring exePath;
	int packLocation;
	std::string resourceName;
};