#pragma once

#include <cstdint>
#include <windows.h>
#include <cstring>
#include <psapi.h>
#include <string>
#include <string_view>
#include <sstream>
#include <vector>

__forceinline uintptr_t FindPattern(uintptr_t start, size_t length, const unsigned char* pattern, const char* mask)
{
	size_t pos = 0;
	auto maskLength = std::strlen(mask) - 1;
	auto startAdress = start;
	for (auto it = startAdress; it < startAdress + length; ++it)
	{
		if (*reinterpret_cast<unsigned char*>(it) == pattern[pos] || mask[pos] == '?')
		{
			if (mask[pos + 1] == '\0')
			{
				return it - maskLength;
			}
			pos++;
		}
		else
		{
			pos = 0;
		}
	}
	return -1;
}
__forceinline uintptr_t FindPattern(HMODULE module, const unsigned char* pattern, const char* mask)
{
	MODULEINFO info = {};
	GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(MODULEINFO));
	return FindPattern(reinterpret_cast<uintptr_t>(module), info.SizeOfImage, pattern, mask);
}
__forceinline uintptr_t FindPattern(HMODULE module, std::string_view ida_pattern)
{
	const auto split_str = [&](const std::string_view s, char delimiter) {
		std::vector<std::string> tokens;
		std::string token;
		std::istringstream tokenStream(s.data());
		while (std::getline(tokenStream, token, delimiter))
		{
			tokens.push_back(token);
		}
		return tokens;
	};

	std::vector<unsigned char> pattern = {};
	std::string mask = {};

	for (auto&& str : split_str(ida_pattern, ' '))
	{
		if (str == "?")
		{
			pattern.push_back('\x00');
			mask += '?';
		}
		else
		{
			pattern.push_back(std::stoi(str.data(), 0, 16));
			mask += 'x';
		}
	}

	return FindPattern(module, pattern.data(), mask.c_str());
}
template <class T>
__forceinline T FindPattern(HMODULE module, std::string_view ida_pattern, const int address_offset, const int instruction_offset, const int instruction_size)
{
	const auto address = FindPattern(module, ida_pattern) + address_offset;
	return (T)(address + *(DWORD*)(address + instruction_offset) + instruction_size);
}
