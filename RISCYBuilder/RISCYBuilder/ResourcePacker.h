#pragma once
#include "Packer.h"

class ResourcePacker : public Packer
{
public:
	ResourcePacker(IMAGE_DOS_HEADER *exe, size_t fSize, Settings setting) : Packer(exe, fSize, setting) { this->setting = setting; }
	bool Pack();

};