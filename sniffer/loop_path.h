/*
    LoopPath is composed of multiple MetaPaths. If there is just one way
    to execute loop then there is only one MetaPath. 
*/

#ifndef _LOOP_PATH_H_
#define _LOOP_PATH_H_


#include "path.h"
#include "simple_path.h"
#include <cstdint>
#include <vector>
#include <memory>
#include <string>


class LoopPath: public Path
{
    public:
        // Constructor should create new current path
        LoopPath();
        // Since loops are reported differently than whole path
        // we can just use SimplePath class to represent path that 
        // was taken inside the loop.

        // This is the current path that is not yet finished
        SimplePath * current_path;

        // This is the vector that has all the paths that were taken
        // since this loop has begun executing. It does not contain copies
        // of same paths but just one instance and then we have the vector
        // times_executed which holds info about how many times the 
        // loop has taken specific path
        std::vector<SimplePath*> paths;
        std::vector<int> times_executed;

        // entry node address
        uint64_t entry_node_addr;
        // exit node address
        uint64_t exit_node_addr;

        // this should take care for ending path
        void end_path();
        // this should take care for starting new path
        void start_path();
        // find if entry node matches 
        bool entry_node_matches(uint64_t entry_addr);
        // There is one more method for ending whole loop
        void end_loop();

        // it adds the transition to current path
        virtual void add_transition(uint64_t src, uint64_t dst);

        operator std::string() const override;

    private:

};

#endif