/*
    MetaPath is just one path that is possible. It can consist
    of SimplePath and LoopPath in a sequence.
*/

#ifndef _META_PATH_H_
#define _META_PATH_H_


#include "path.h"
#include <list>


class MetaPath
{
    public:
        MetaPath();
        std::list<Path> path;
        Path get_last();
    private:

};

#endif