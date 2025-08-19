/*
    SimplePath is the simples block of them all (Path types). It just contains
    list of transitions in the type of (SRC, DEST). It shouldn't contain nothing else.
*/

#ifndef _SIMPLE_PATH_H_
#define _SIMPLE_PATH_H_


#include "path.h"
#include <vector>
#include <tuple>
#include <cstdint>
#include <string>


class SimplePath: public Path
{
    public:
        SimplePath();
        // This is the holder of transitions that the program will take.
        std::vector<std::tuple<int, int>> transitions;
        virtual void add_transition(uint64_t src, uint64_t dst);
        bool equal(SimplePath * sp);

        operator std::string() const override;
    private:

};

#endif
