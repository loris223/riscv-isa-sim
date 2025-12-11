/****************
 * Author: Loris
 * Date: 2025-03-31
 * Description:
 * Basic idea of the sniffer will be to obtain the opcode
 * from the main execution loop of spike simulator. On that
 * opcode there will be performed filtering that only extracts 
 * instructions that branch or jump somewhere. With those 
 * instructions appropriate action should be taken. For
 * starting point the action will be print.
 * 
 * The sniffer should be made as a class, because for now
 * I believe it to be a hardware extension wired directly
 * to the processor fetch/decode/execute cycle. So in summary it could be
 * a component attached to that pipeline.
 ****************/

#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#ifndef SNIFFER_TEST_MODE
#define SNIFFER_TEST_MODE 0  // Default to normal mode
#endif

#include "path.h"
#include "simple_path.h"
#include "loop_path.h"
#include <cstdio>
#include <string>
#include <cstdint>
#include <cstdlib>
#include "../riscv/decode.h"
#include <capstone/capstone.h>
#include <memory>
#include <sodium.h>
#include <optional>
#include <vector>


std::array<uint8_t, crypto_generichash_BYTES>  hash_branch_addrs(const std::array<uint8_t, crypto_generichash_BYTES>* prev_hash, uint64_t src, uint64_t dst);

/*****************NODE******************* */
// Node class to hold entry and exit addresses for branch instructions
class Node {
public:
    uint64_t entry_addr; // Source address
    uint64_t exit_addr;  // Destination address
    bool entry_set;      // Flag to track if entry address has been set
    bool exit_set;       // Flag to track if exit address has been set

    // Constructor with both addresses
    Node(uint64_t entry, uint64_t exit) : 
        entry_addr(entry), exit_addr(exit), entry_set(true), exit_set(true) {}
    
    // Constructor with just entry address
    explicit Node(uint64_t entry) : 
        entry_addr(entry), exit_addr(0), entry_set(true), exit_set(false) {}
    
    // Default constructor (no addresses set)
    Node() : 
        entry_addr(0), exit_addr(0), entry_set(false), exit_set(false) {}
    
    // Set the entry address
    void set_entry(uint64_t entry) {
        entry_addr = entry;
        entry_set = true;
    }
    
    // Set the exit address
    void set_exit(uint64_t exit) {
        exit_addr = exit;
        exit_set = true;
    }
    
    // Check if entry address has been set
    bool has_entry() const {
        return entry_set;
    }
    
    // Check if exit address has been set
    bool has_exit() const {
        return exit_set;
    }
    
    // Check if both addresses have been set
    bool is_complete() const {
        return entry_set && exit_set;
    }

    // Equality operator for comparing nodes
    bool operator==(const Node& other) const {
        // If both have entry set, compare entries
        if (entry_set && other.entry_set && entry_addr != other.entry_addr) {
            return false;
        }
        
        // If both have exit set, compare exits
        if (exit_set && other.exit_set && exit_addr != other.exit_addr) {
            return false;
        }
        
        return true;
    }

    // Print node information
    void print() const {
        if (entry_set && exit_set) {
            printf("Node: entry=0x%" PRIx64 ", exit=0x%" PRIx64 "\n", entry_addr, exit_addr);
        } else if (entry_set) {
            printf("Node: entry=0x%" PRIx64 ", exit=not set\n", entry_addr);
        } else if (exit_set) {
            printf("Node: entry=not set, exit=0x%" PRIx64 "\n", exit_addr);
        } else {
            printf("Node: entry=not set, exit=not set\n");
        }
    }

    // Generate hash for this node
    // Only generates hash if both addresses are set
    std::optional<std::array<uint8_t, crypto_generichash_BYTES>> hash() const {
        if (!entry_set || !exit_set) {
            return std::nullopt;
        }
        return hash_branch_addrs(NULL, entry_addr, exit_addr);
    }
};



class sniffer_t
{
 public:
    sniffer_t();
    ~sniffer_t();
    void invoke(regfile_t<reg_t, NXPR, true> XPR, uint64_t pc, insn_t insn);
    void invoke_process(regfile_t<reg_t, NXPR, true> XPR, uint64_t pc, insn_t insn);
    void cap_disassemble(uint64_t insn_, insn_t insn);
    void cap_disassemble(const uint8_t * insn_, insn_t insn);
    void hash_update();
    crypto_generichash_state hash_state;
    bool hash_initialized = false;
    size_t nodes_hashed = 0;
    std::array<uint8_t, crypto_generichash_BYTES> get_final_hash();

    // this will be the vector which holds the current path
    std::vector<Path*> path_stack;

    // this will be the vector that will contain all loops that
    // were ever executed
    std::vector<Path*> all_loops;
    // this will hold the hash values of the path when the loop 
    // starts to execute
    //std::vector<std::array<uint8_t, crypto_generichash_BYTES>> loops_hash_entries;


    std::string snif_start_addr_str = "SNIFFER_START_ADDR";
    std::string snif_end_addr_str = "SNIFFER_END_ADDR";
    std::string snif_follow_functions_str = "SNIFFER_FOLLOW_FUNS";
    std::string snif_banned_addrs_str = "SNIFFER_BANNED_ADDRS";
    bool snif_addrs_set = false;
    uint64_t sniffer_start_addr = 0;
    uint64_t sniffer_end_addr = 0;
    bool sniffer_monitoring = false;
    bool snif_follow_functions = false;
    std::vector<uint64_t> snif_banned_addrs;
    

    
 private:
    uint64_t get_src_addr(uint64_t pc);
    uint64_t get_dst_addr(regfile_t<reg_t, NXPR, true> XPR, uint64_t pc, insn_t insn, cs_insn * cs_insn_);
    void capstone_version();
    void capstone_close();
    void capstone_init();
    void cap_disassemble_all(const uint8_t * insn_, insn_t insn);
    void capstone_operands_print(cs_insn  cs_insn_);
    void capstone_operands_numbers_print(cs_insn * cs_insn_);
    void get_signed_offset(cs_insn cs_insn_, insn_t insn);
    uint64_t get_register_value(regfile_t<reg_t, NXPR, true> XPR, int reg);
    std::unique_ptr<cs_insn> cap_disassemble_single(const uint8_t * insn_, uint64_t insn_address);
    int t_called = 0;

    // CAPSTONE variables
    // This handle will be used at every API of Capstone.
    csh handle;
    // points to a memory containing all disassembled instructions
    cs_insn *cap_insn;

    // Node
    Node node_cur;
    
};


#endif