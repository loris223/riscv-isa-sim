/* TODO
 */

#ifndef _PATH_H_
#define _PATH_H_

#include <cstdint>
#include <string>
#include <sodium.h>
#include <array>

class Path
{
    public:
        virtual ~Path() = default;
        virtual void add_transition(uint64_t src, uint64_t dst) = 0;
        virtual operator std::string() const = 0;
        std::array<uint8_t, crypto_generichash_BYTES> current_hash = {};
    private:

};

#endif