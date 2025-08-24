#include "simple_path.h"
#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>


SimplePath::SimplePath(){

}

void SimplePath::add_transition(uint64_t src, uint64_t dst){
    this->transitions.push_back(std::tuple<int, int>(src, dst));
}

bool SimplePath::equal(SimplePath * sp){
    if(this->transitions.size() != sp->transitions.size()){
        return false;
    }
    for(uint64_t i = 0; i < this->transitions.size(); i++){
        // So the tuple is supposed to have built-in comparision operators
        // that work element-by-element.
        if(this->transitions[i] != sp->transitions[i]){
            return false;
        }
    }
    return true;
}


SimplePath::operator std::string() const {
    std::ostringstream oss;
    oss << "SimplePath[";
    for (const auto& [src, dst] : transitions) {
        oss << " (0x" << std::hex << std::setw(8) << std::setfill('0') << src 
            << " -> 0x" << std::hex << std::setw(8) << std::setfill('0') << dst << ")";
    }
    oss << " ]";

    // Add the hash as a hex string
    oss << " Hash: 0x";
    // Loop through each byte in the hash array and print it as two hex digits
    for (const auto& byte : current_hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return oss.str();
}