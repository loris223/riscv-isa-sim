#include "sniffer.h"
#include <cstdio>
#include <cstdint>
#include "../riscv/decode.h"
#include "../riscv/processor.h"
#include <bitset>
#include <iostream>
#include <utility>
#include <memory>
#include <sodium.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <array>
#include <iomanip>

#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>

bool is_function_call(insn_t insn, cs_insn* cs_insn_);
uint64_t get_dst_addr_inverse(regfile_t<reg_t, NXPR, true> XPR,
                                uint64_t pc, insn_t insn, cs_insn* cs_insn_);
uint64_t get_dst_addr(regfile_t<reg_t, NXPR, true> XPR,
                                uint64_t pc, insn_t insn, cs_insn* cs_insn_);

/**************CAPSTONE METHODS**************** */
// Close capstone handle
void sniffer_t::capstone_close(){
    cs_close(&handle);
}

// Initialize capstone library via handle and set custom options
void sniffer_t::capstone_init(){
    // cs_open(the hardware architecture, hardware mode and pointer to handle)
    if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV32, &handle) != CS_ERR_OK){
        std::cerr << "Failed to initialize Capstone" << std::endl;
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

// Write out capstone version
void sniffer_t::capstone_version(){
    int major, minor;
    cs_version(&major, &minor);
    printf("Capstone v%d.%d\n", major, minor);
}

// Print out instruction in detail
// for now only BEQ supported
void sniffer_t::capstone_operands_print(cs_insn cs_insn_){
    if (cs_insn_.id == RISCV_INS_BEQ) {
        cs_riscv* riscv = &(cs_insn_.detail->riscv);
        printf("BEQ operands:\n");
        printf("  rs1: %s\n", cs_reg_name(handle, riscv->operands[0].reg));
        printf("  rs2: %s\n", cs_reg_name(handle, riscv->operands[1].reg));
        printf("  offset: %ld\n", riscv->operands[2].imm);
    }
}

// Print out how many operands of each type instruction has
// Immediate / Register / Memory
void sniffer_t::capstone_operands_numbers_print(cs_insn * cs_insn_){
    int cs_op_count_imm = cs_op_count(handle, cs_insn_, RISCV_OP_IMM);
    int cs_op_count_reg = cs_op_count(handle, cs_insn_, RISCV_OP_REG);
    int cs_op_count_mem = cs_op_count(handle, cs_insn_, RISCV_OP_MEM);
    printf("##### OPERANDS #####\n");
    printf("Number of immediate operands: %d\n", cs_op_count_imm);
    printf("Number of register operands: %d\n", cs_op_count_reg);
    printf("Number of memory operands: %d\n", cs_op_count_mem);
    printf("##### -------  #####\n");
}

// It dissassembles single instructions and returns capstone cs_insn pointer to object
// of that instruction and nullptr if disasseble fails.
std::unique_ptr<cs_insn> sniffer_t::cap_disassemble_single(const uint8_t * insn_, uint64_t insn_address){
    

    int count = cs_disasm(handle, insn_, sizeof(insn_)-1, insn_address, 0, &cap_insn);
	if (count == 1) {
        
        // Allocate and copy the instruction into a smart pointer
        auto result = std::make_unique<cs_insn>();
        *result = cap_insn[0]; // Copy the data
		cs_free(cap_insn, count);
        return result;
	} 
    else if(count > 1){
		printf("ERROR: Multiple instructions found in a code that should contain single instruction!\n");
    }
    else
		printf("ERROR: Failed to disassemble given instruction!\n");
    return nullptr;
}

// Returns content of the queried register
uint64_t sniffer_t::get_register_value(regfile_t<reg_t, NXPR, true> XPR, int reg){
    return XPR[reg];
}
    
void sniffer_t::get_signed_offset(cs_insn cs_insn_, insn_t insn){
    switch (cs_insn_.id) {
        // Conditional branches
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
            printf("Immediate value: %ld\n", insn.sb_imm());
            printf("This is a conditional branch.!\n");
            break;
        // Unconditional jumps
        case RISCV_INS_JAL:
        case RISCV_INS_JALR:
            printf("This is a unconditional branch.!\n");
            break;
        default:
            break;
    }
}

void sniffer_t::cap_disassemble_all(const uint8_t * insn_, insn_t insn){
    int count = cs_disasm(handle, insn_, sizeof(insn_)-1, 0x1000, 0, &cap_insn);
	if (count > 0) {
		int j;
		for (j = 0; j < count; j++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", cap_insn[j].address, cap_insn[j].mnemonic,
					cap_insn[j].op_str);
            cap_insn[j].op_str;
            cs_detail *detail = cap_insn[j].detail;
            capstone_operands_print(cap_insn[j]);
            
		}

		cs_free(cap_insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

}

const uint8_t* uint64_to_bytes(uint64_t value, uint8_t* buffer) {
    memcpy(buffer, &value, sizeof(value));
    return buffer;
}

std::unique_ptr<uint8_t[]> uint64_to_bytes_heap(uint64_t value) {
    auto buffer = std::make_unique<uint8_t[]>(sizeof(uint64_t));  // Allocates 8 bytes
    memcpy(buffer.get(), &value, sizeof(uint64_t));  // Copy the bytes
    return buffer;  // Ownership is transferred to the caller
}

void sniffer_t::cap_disassemble(uint64_t insn_, insn_t insn){
    uint8_t buffer[8];
    cap_disassemble_all(uint64_to_bytes(insn_, buffer), insn);
}

void sniffer_t::cap_disassemble(const uint8_t * insn_, insn_t insn){
    cap_disassemble_all(insn_,insn);
}

bool is_branch(cs_insn cs_insn_){
    switch (cs_insn_.id) {
        // Conditional branches
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
            return true;
            break;
        // Unconditional jumps
        case RISCV_INS_JAL:
        case RISCV_INS_JALR:
        default:
            return false;
            break;
    }
}

uint64_t convert_str_to_uint64_t(const char * value){
    if (strlen(value) > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        return strtoull(value, nullptr, 16);
    }
    
    // Handle decimal format
    return strtoull(value, nullptr, 10);
}

bool is_branch_or_jump(cs_insn cs_insn_){
    switch (cs_insn_.id) {
        // Conditional branches
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
        // Unconditional jumps
        case RISCV_INS_JAL:
        case RISCV_INS_JALR:
            return true;
            break;
        default:
            return false;
            break;
    }
}

// Initialize sniffer object, init capstone
sniffer_t::sniffer_t() {
    printf("Sniffer created\n");
    const char * start_addr = std::getenv(this->snif_start_addr_str.c_str());
    const char * end_addr = std::getenv(this->snif_end_addr_str.c_str());
    if (start_addr && end_addr){
        std::cout << "Sniffer will start monitoring at address: " << start_addr << '\n';
        std::cout << "Sniffer will end monitoring at address: " << end_addr << '\n';
        this->snif_addrs_set = true;
        this->sniffer_start_addr = convert_str_to_uint64_t(start_addr);
        this->sniffer_end_addr = convert_str_to_uint64_t(end_addr);
        
        
    }
    else{
        std::cout << "Sniffer got no monitoring address and will not engage in act."<< '\n';
    }


    const char * follow_funs = std::getenv(this->snif_follow_functions_str.c_str());
    if (follow_funs){
        std::string value = follow_funs;
        this->snif_follow_functions = (value == "1" || value == "TRUE");
        std::cout << "Sniffer follows function calls."<< '\n';
    }
    else{
        std::cout << "Sniffer will not follow function calls."<< '\n';
    }


    const char * banned_addrs = std::getenv(this->snif_banned_addrs_str.c_str());
    if (banned_addrs){
        std::string value = banned_addrs;

        std::istringstream iss(value);
        std::string token;

        while(std::getline(iss, token, ',')){
            token.erase(std::remove_if(token.begin(), token.end(), ::isspace), token.end());

            if (!token.empty()){
                try {
                    uint64_t addr = std::stoull(token, nullptr, 0);
                    this->snif_banned_addrs.push_back(addr);
                }catch(const std::exception& e){
                    std::cerr << "Warning: Invalid hex address '" << token << "'" << std::endl;
                }
            }
        }
    }
    else{std::cout << "Sniffer banned addresses not provided."<< '\n';}

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
    }
    capstone_init();
    capstone_version();
    SimplePath * sp = new SimplePath();
    this->path_stack.push_back(sp);
};

// Destroy sniffer object, destroy capstone
sniffer_t::~sniffer_t() {
    std::cout << "=== Printing All Loops ===\n";
    for (Path* path : all_loops) {
        if (path) {
            // Uses the virtual operator std::string()
            std::cout << static_cast<std::string>(*path) << "\n";
        }
    }

    std::cout << "\n=== Printing Top of Stack ===\n";
    if (!path_stack.empty() && path_stack.back()) {
        // Print the last element in stack
        std::cout << static_cast<std::string>(*path_stack.back()) << "\n";
    } else {
        std::cout << "Stack is empty or invalid.\n";
    }

    
    const char * riscv_path = std::getenv("RISCV");
    std::string output_path = std::string(riscv_path) + "/sniffer_output";
    std::ofstream out_file(output_path);
    if(out_file.is_open()){
        printf("Printing hashes to a file.\n");
        
        // LOOPS (file)
        out_file << "LOOPS" << std::endl;
        for(Path * path : all_loops){
            if (LoopPath* loopPath = dynamic_cast<LoopPath*>(path)){
                int index = 0;
                // Write entry hash
                out_file << "0x";
                for (const auto& byte : loopPath->entry_hash) {
                    out_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                out_file << std::endl;
                for(SimplePath * sp : loopPath->paths){
                    out_file << "0x";
                    for (const auto& byte : sp->current_hash) {
                        out_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                    }
                    out_file << std::endl;
                    out_file << std::dec << loopPath->times_executed[index] << std::endl;
                    index++;
                }
                out_file << std::endl;
            }
            
        }

        // PATH
        out_file << "PATH" << std::endl;
        out_file << "0x";
        for (const auto& byte : (path_stack.back())->current_hash) {
            out_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        out_file << std::endl;
    }
    else{
        std::cerr << "Error: Could not open file for writing!" << std::endl;
    }
    out_file.close();

    printf("Sniffer destroyed\n");
    capstone_close();
};


// Update the hash state with a new node
void sniffer_t::hash_update() {
    // Skip if node is not complete (missing entry or exit)
    if (!node_cur.is_complete()) {
        std::cerr << "The node is not complete!" << std::endl;
        return;
    }
    
    // Initialize hash state if this is the first update
    if (!hash_initialized) {
        crypto_generichash_init(&hash_state, nullptr, 0, crypto_generichash_BYTES);
        hash_initialized = true;
    }
    
    // Create a buffer containing both addresses
    struct {
        uint64_t entry;
        uint64_t exit;
    } addr_pair = { node_cur.entry_addr, node_cur.exit_addr };
    
    // Update hash with both addresses in a single operation
    crypto_generichash_update(&hash_state, 
                            reinterpret_cast<const uint8_t*>(&addr_pair),
                            sizeof(addr_pair));
    
    // Increment the number of nodes hashed
    nodes_hashed++;
    
    if (nodes_hashed <= 10) {  // Limit output for performance
        printf("Hash updated with node: entry=0x%" PRIx64 ", exit=0x%" PRIx64 "\n", 
               node_cur.entry_addr, node_cur.exit_addr);
    }
}

// Get the final hash
std::array<uint8_t, crypto_generichash_BYTES> sniffer_t::get_final_hash() {
    std::array<uint8_t, crypto_generichash_BYTES> final_hash;
    
    // If hash was never initialized, return zeros
    if (!hash_initialized) {
        final_hash.fill(0);
        return final_hash;
    }
    
    // Create a copy of the hash state to avoid finalizing the original
    crypto_generichash_state state_copy = hash_state;
    
    // Finalize the hash
    crypto_generichash_final(&state_copy, final_hash.data(), final_hash.size());
    
    return final_hash;
}

std::array<uint8_t, crypto_generichash_BYTES>  hash_branch_addrs(
    const std::array<uint8_t, crypto_generichash_BYTES>* prev_hash, uint64_t src, uint64_t dst
    ) {

    std::array<uint8_t, crypto_generichash_BYTES> hash;
    crypto_generichash_state state;

    

    // Initialize BLAKE2b
    crypto_generichash_init(&state, nullptr, 0, hash.size());

    if (prev_hash != nullptr) {
        // If a valid pointer was provided, use the array it points to
        crypto_generichash_update(&state, prev_hash->data(), prev_hash->size());
    } else {
        // If the pointer was null, use a zero-initialized array instead
        std::array<uint8_t, crypto_generichash_BYTES> zero_hash = {};
        crypto_generichash_update(&state, zero_hash.data(), zero_hash.size());
    }

    // Hash source address
    crypto_generichash_update(&state, 
                            reinterpret_cast<const uint8_t*>(&src),
                            sizeof(src));
    
    // Hash destination address
    crypto_generichash_update(&state,
                            reinterpret_cast<const uint8_t*>(&dst),
                            sizeof(dst));

    // Finalize hash
    crypto_generichash_final(&state, hash.data(), hash.size());

    return hash;
}


// This should be called always after we have found
// the function that we are following. We won't follow
// whole program but just some parts of it. It is not of
// importance to follow everything but just to demonstrate 
// the concept. There should be a part of the sniffer that will
// keep track of where to start tracking and where to end. When
// tracking this should be main function.
void sniffer_t::invoke_process(regfile_t<reg_t, NXPR, true> XPR, uint64_t pc, insn_t insn){
   //          0. There should be stack established in sniffer where the path
    //              will be tracked.
    //              - It is meta_path

    //          1. Filter the instructions for BRANCHES & JUMPS
    
    // transform uint64 to bytes using smart pointer
    // diassemble instruction
    auto buffer = uint64_to_bytes_heap(insn.bits());
    auto cs_insn_ = cap_disassemble_single(buffer.get(), pc);

    // Return if disassembly failed
    if(!cs_insn_){
        return;
    }

    // We are only interested in certain type of instructions and
    // we should just skip other ones.
    if(!is_branch_or_jump(*cs_insn_)){
        return;
    }

    //printf("It is branch or jump so we proceed.\n");     // 32-bit hex

    // Get current path element
    // Will do with a reference for a change
    // of pointer.
    Path* current_path = this->path_stack.back();

    // Get current SRC
    uint64_t current_src = get_src_addr(pc);

        //          1.5. Evaluate insn
    // If there is branch there is also option about the path not taken.
    // For example if the loop was never taken should the branch node of
    // loop be taken into the path or not? Probably not since the path
    // hash should resume from exit node. Therefore we should also notice
    // the case where the not taken destination address indicates loop.
    // It is not clear for now where this hash will be.
    uint64_t current_dst = ::get_dst_addr(XPR, pc, insn, cs_insn_.get());
    uint64_t not_taken_dst = 0;
    if (is_branch(*cs_insn_)){
        not_taken_dst = get_dst_addr_inverse(XPR, pc, insn, cs_insn_.get());
    }

    //             1.625 Check if it is return statement
    // Return statement will look like jalr 0, 1, 0

    //             1.75 Check if it is function call
    if (is_function_call(insn, cs_insn_.get())){
        // check if a function is banned
        bool ban_addr = std::find(this->snif_banned_addrs.begin(),
                                this->snif_banned_addrs.end(),
                                pc) != this->snif_banned_addrs.end();
        
        if(this->snif_follow_functions && (!ban_addr)){
            // add transition
            current_path->add_transition(current_src, current_dst);
            // hash
            if (LoopPath* loopPath = dynamic_cast<LoopPath*>(current_path)){
                loopPath->current_path->current_hash = hash_branch_addrs(&(loopPath->current_path->current_hash), current_src, current_dst);
            }
            else{
                current_path->current_hash = hash_branch_addrs(&(current_path->current_hash), current_src, current_dst);
            }
        }
        else{
            // if function is banned or sniffer is not following
            // functions then stop monitoring and set another 
            // monitoring start address
            this->sniffer_monitoring = false;
            this->sniffer_start_addr = pc + 4;
        }
        
        return;
    }


    //          2. Check for the loop end (end is considered the first 
    //              basic block after loop and in this case just first 
    //              branch out of the loop)
    //              This should be done with SRC address of branch/jump
    //              and note that this is just program counter. If the path
    //              in the stack is just SimplePath then leave this step.
    // If this is the loop end then:
    //      - Process last path + info about loop
    //      - Pop the loop from stack
    //      - Somehow assign this exited loop in the new current path
    //          We don't actually need to assign this exited loop to current
    //          path since we just need to report this executed loop sometime.
    //          We just add it to list where the executed loops are.

    // Check if this is LoopPath
    if (LoopPath* loopPath = dynamic_cast<LoopPath*>(current_path)) {
        //printf("We are in a loop currently\n");
        uint64_t exit_node_addr = loopPath->exit_node_addr;
        if(current_dst >= exit_node_addr){
            //printf("We have exited the loop!\n");
            // This is loop exit
            // TODO
            loopPath->end_path();
            loopPath->end_loop();
            this->all_loops.push_back(current_path);
            this->path_stack.pop_back();
        }

    }

    
    //          3. Check for backward jump -> Detect loop
    //              This should create new loop if necessary (look for
    //              what is current element of the stack and if the entry
    //              addr matches this one it is just the same loop)
    //          IF loop is the same:
    //              - process current path
    //          ELSE:
    //              - add insn to current path
    //              - make new loop
    //              - mark the position of the new loop within the previous
    //              - continue
    // For now we believe that only branches do loops
    // So look for branch and that the destination address
    // goes backwards
    current_path = this->path_stack.back();
    if(is_branch(*cs_insn_) && (current_dst < current_src)){
        //printf("We have detected the loop\n");
        // If we detect a loop we should consider two cases
        // - the same loop (we don't do anything)
        //definitely a loop here inside
        LoopPath* loopPath = dynamic_cast<LoopPath*>(current_path);
        if(loopPath && loopPath->entry_node_matches(current_dst)){
            //printf("Same loop!\n");
            // So the loop does at least one more execution.
            loopPath->end_path();
            loopPath->start_path();

        }
        else{
            // new loop
            LoopPath* new_loop = new LoopPath();
            new_loop->entry_node_addr = current_dst;
            // Here we have established that this exit node address
            // is not always correct. If I remember correctly loop
            // with two conditions bounded by or contradict that.
            // We should just add additional check. So for example
            // when the exit node is reached we should check if it
            // jumps to the same entry node as the loop that was "supposed"
            // to end. And if that is the case we do not terminate that loop
            // we just fix the exit node address. But for now this is ok.
            new_loop->exit_node_addr = current_src + 4;
            new_loop->entry_hash = current_path->current_hash;
            path_stack.push_back(new_loop);

        }
    }

    //          4. Add INSN to Path
    //printf("Add transition to the current path!\n");
    current_path = this->path_stack.back();
    current_path->add_transition(current_src, current_dst);
    if (LoopPath* loopPath = dynamic_cast<LoopPath*>(current_path)){
        loopPath->current_path->current_hash = hash_branch_addrs(&(loopPath->current_path->current_hash), current_src, current_dst);
    
    }
    else{
        current_path->current_hash = hash_branch_addrs(&(current_path->current_hash), current_src, current_dst);
        
    }

}

// This method will be main entry point to the sniffer object which
// will be invoked every time when instruction will be executed in Spike.
// Here should happen all but the final results.
void sniffer_t::invoke(regfile_t<reg_t, NXPR, true> XPR, uint64_t pc, insn_t insn) {
    //printf("Sniffer invoked\n");
    uint32_t pc_32bit = (uint32_t) (pc & 0xFFFFFFFF);
    if ((this->sniffer_start_addr & 0xFFFFFFFF) == pc_32bit){
        this->sniffer_monitoring = true;
        printf("Starting monitoring at PC:  0x%08" PRIx32 "\n", pc_32bit);     // 32-bit hex
    }

    if (((this->sniffer_end_addr & 0xFFFFFFFF) - 4) == pc_32bit){
        this->sniffer_monitoring = false;
    }

    if(this->sniffer_monitoring){
        this->invoke_process(XPR, pc, insn);
    }

   
    
    
    
    t_called++;
    if (t_called <= 0) {
        if (const char* env_p = std::getenv("RISCV"))
            std::cout << "Your RISCV variable is: " << env_p << '\n';
        printf("Sniffer invoked\n");
        
        
        printf("Sniffer invoked\n");
        printf("Raw PC:      %" PRIu64 "\n", pc);               // Debug
        printf("Correct PC:  0x%08" PRIx32 "\n", pc_32bit);     // 32-bit hex

        // Nodes (1)
        if(!node_cur.has_entry()){
            // if there is no entry address in node we should add it
            node_cur.set_entry(pc);
        }

        // transform uint64 to bytes using smart pointer
        // diassemble instruction
        auto buffer = uint64_to_bytes_heap(insn.bits());
        auto cs_insn_ = cap_disassemble_single(buffer.get(), pc);

        // Return if disassembly failed
        if(!cs_insn_){
            return;
        }

        // We are only interested in certain type of instructions and
        // we should just skip other ones.
        if(!is_branch_or_jump(*cs_insn_)){
            return;
        }


        // Nodes (2)
        // If we came all way to here it means that the current BBL ends with
        // this instruction. We should change node_cur accordingly.
        node_cur.set_exit(pc);
        node_cur = Node();

        // Obtain src and dst addresses
        uint64_t addr_src = get_src_addr(pc);
        uint64_t addr_dst = ::get_dst_addr(XPR, pc, insn, cs_insn_.get());

        // Calculate hash
        auto hash = hash_branch_addrs(NULL, addr_src, addr_dst);

        

        // Print the hash
        printf("Branch hash: ");
        for (const auto& byte : hash) {
            printf("%02x", byte);
        }
        printf("\n");


        std::bitset<32> b_(insn.bits());
        printf("Instruction is: \n");
        std::cout << b_ << '\n';
        //printf("The opcode is:%lu\n", insn.opcode());
    }
};

// Helper: Evaluate conditional branch
bool evaluate_branch_condition(cs_insn* insn, uint64_t rs1_val, uint64_t rs2_val) {
    switch (insn->id) {
        case RISCV_INS_BEQ:  return rs1_val == rs2_val;
        case RISCV_INS_BNE:  return rs1_val != rs2_val;
        case RISCV_INS_BLT:  return (int64_t)rs1_val < (int64_t)rs2_val;
        case RISCV_INS_BGE:  return (int64_t)rs1_val >= (int64_t)rs2_val;
        case RISCV_INS_BLTU: return rs1_val < rs2_val;
        case RISCV_INS_BGEU: return rs1_val >= rs2_val;
        default: return false;
    }
}

// Helper: Calculate branch target
uint64_t calculate_branch_target(uint64_t pc, insn_t insn, bool taken) {
    return taken ? pc + insn.sb_imm() : pc + 4;
}

// Helper: Calculate JAL target
uint64_t calculate_jal_target(uint64_t pc, insn_t insn) {
    return pc + insn.uj_imm();
}

// Helper: Calculate JALR target
uint64_t calculate_jalr_target(regfile_t<reg_t, NXPR, true> XPR, 
                              cs_riscv_op* operands, int64_t offset) {
    uint64_t base = XPR[operands[0].reg];
    return (base + offset) & ~(uint64_t)1;
}


bool is_function_call(insn_t insn, cs_insn* cs_insn_){
    // Function call is only possible with jal and jalr instructions
    if (cs_insn_->id == RISCV_INS_JAL ||
        cs_insn_->id == RISCV_INS_JALR){
        // We are interested in rd register which indicates
        // whether it is a function call or not. If it is
        // not a function all then linking should happen
        // with register 0, therefore doing nothing.
        if (insn.rd() != 0){
            return true;
        }
    }
    return false;

}


uint64_t sniffer_t::get_src_addr(uint64_t pc) {
    return pc;
};

uint64_t get_dst_addr(regfile_t<reg_t, NXPR, true> XPR,
                                uint64_t pc, insn_t insn, cs_insn* cs_insn_) {
    if (!cs_insn_ || !cs_insn_->detail) return pc + 4;  // Default to next instruction

    cs_riscv* riscv = &(cs_insn_->detail->riscv);
    //printf("%d", cs_insn_->id);
    
    switch (cs_insn_->id) {
        //case RISCV_INS_C_BEQZ:
        //    break;
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
            if (riscv->op_count >= 2) {
                uint64_t rs1_val = XPR[insn.rs1()];
                uint64_t rs2_val = XPR[insn.rs2()];
                bool taken = evaluate_branch_condition(cs_insn_, rs1_val, rs2_val);
                
                return calculate_branch_target(pc, insn, taken);
            }
            break;

        case RISCV_INS_JAL:
            return calculate_jal_target(pc, insn);

        case RISCV_INS_JALR:
            return (XPR[insn.rs1()] + insn.i_imm()) & ~(uint64_t)1;
            break;
        default:
            printf("Problem, instruction not supported.\n");
            break;
    }

    return pc + 4;  // Default fallthrough
}

uint64_t get_dst_addr_inverse(regfile_t<reg_t, NXPR, true> XPR,
                                uint64_t pc, insn_t insn, cs_insn* cs_insn_) {
    if (!cs_insn_ || !cs_insn_->detail) return pc + 4;  // Default to next instruction

    cs_riscv* riscv = &(cs_insn_->detail->riscv);
    
    switch (cs_insn_->id) {
        case RISCV_INS_BEQ:
        case RISCV_INS_BNE:
        case RISCV_INS_BLT:
        case RISCV_INS_BGE:
        case RISCV_INS_BLTU:
        case RISCV_INS_BGEU:
            if (riscv->op_count >= 2) {
                uint64_t rs1_val = XPR[insn.rs1()];
                uint64_t rs2_val = XPR[insn.rs2()];
                bool taken = evaluate_branch_condition(cs_insn_, rs1_val, rs2_val);
                taken = !taken;
                return calculate_branch_target(pc, insn, taken);
            }
            break;

        case RISCV_INS_JAL:
            return calculate_jal_target(pc, insn);

        case RISCV_INS_JALR:
            if (riscv->op_count >= 1) {
                return calculate_jalr_target(XPR, riscv->operands, insn.i_imm());
            }
            break;
    }

    return pc + 4;  // Default fallthrough
}