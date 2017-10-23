#include "stdafx.h"
#include "ResourcePacker.h"


bool ResourcePacker::Pack()
{
	ZLIBcompress();
	//Crypt();

	parentPEd->WriteResource(this->packedBinary, this->packedBinary.size(), this->setting.resourceName);
	if (!DropPackedExe())
		return false;
	return true;
}
