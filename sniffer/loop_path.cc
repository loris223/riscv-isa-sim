#include "loop_path.h"
#include <memory>
#include <sstream>
#include <iomanip>

LoopPath::LoopPath(){
    // create new SimplePath
    this->current_path = new SimplePath();
}

void LoopPath::end_path(){
    // increment counter and make new SimplePath for current path
    // if same path already exists
    SimplePath * finished_path = this->current_path;
    //this->current_path = new SimplePath();
    this->current_path = NULL;
    

    for(uint64_t i = 0; i < this->paths.size(); i++){
        bool same_path_bool = finished_path->equal(this->paths[i]);
        if(same_path_bool){
            this->times_executed[i] += 1;
            return;
        }
    }
    // Add new path, add counter and make new SimplePath
    // if the path does not already exist
    this->times_executed.push_back(1);
    this->paths.push_back(finished_path);
}


void LoopPath::start_path(){
    // For now we will just add new SimplePath
    this->current_path = new SimplePath();
}

bool LoopPath::entry_node_matches(uint64_t entry_addr){
    // by entry node address we match if the loops are the same
    if(this->entry_node_addr == entry_addr){
        return true;
    }
    else{
        return false;
    }
}

void LoopPath::end_loop(){
    // For now it can be empty
}

void LoopPath::add_transition(uint64_t src, uint64_t dst){
    // We are actually just upadting the SimplePath here
    this->current_path->add_transition(src, dst);
}

LoopPath::operator std::string() const {
    std::ostringstream oss;
    oss << "LoopPath[entry=0x" << std::hex << std::setw(8) << std::setfill('0') << entry_node_addr 
        << ", exit=0x" << std::hex << std::setw(8) << std::setfill('0') << exit_node_addr 
        << ", entry_hash=0x";
    
    // Add the entry_hash in hex format
    for (const auto& byte : entry_hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    oss << ", paths=[";

    for (size_t i = 0; i < paths.size(); i++) {
        if (i != 0) oss << ", ";
        oss << "(" << static_cast<std::string>(*paths[i]) 
            << ", executed=" << std::dec << times_executed[i] << "x)";  // Keep count in decimal
    }

    oss << "], current_path=";
    if (current_path) {
        oss << static_cast<std::string>(*current_path);
    } else {
        oss << "null";
    }
    oss << "]";
    return oss.str();
}