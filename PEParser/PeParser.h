#pragma once
#include <iostream>
#include <stdexcept>
#include <string>
#include <windows.h>

#include "tchar.h"

#if defined(UNICODE) || defined(_UNICODE)
#define cout wcout
#define cerr wcerr
#endif