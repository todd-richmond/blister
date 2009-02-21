#include "stdapi.h"

// hack to work around broken Microsoft libraries
#if !defined(_DLL)

#ifdef std
#undef std
#endif

extern "C" {
    fpos_t std::_Fpz = {0, 0};
}

#endif

