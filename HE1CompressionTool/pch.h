#pragma once

// Standard C++ headers
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <future>
#include <thread>
#include <map>
#include <algorithm>
#include <mutex>

// Windows headers
#include <Windows.h>
#include <fci.h>
#include <fdi.h>

// External dependencies
extern "C" {
#include "../Deps/mspack/mspack.h"
#include "../Deps/mspack/lzx.h"
}
