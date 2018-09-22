'use strict';

rpc.exports = {
    get_aot_module_addr: function() {
    
    },
    
    get_byte: function(addr) {
        return Memory.readU8(addr);
    },
    get_word: function(addr) {
        return Memory.readU16(addr);
    },
    get_dword: function(addr) {
        return Memory.readU32(addr);
    },
    get_qword: function(addr) {
        return Memory.readU64(addr);
    },
    get_bytes: function(addr, size) {
        return Memory.readByteArray(addr, size);
    },
};
