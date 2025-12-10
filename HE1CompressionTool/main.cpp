#include "pch.h"

namespace fs = std::filesystem;
std::mutex cout_mutex;
#define COMPRESSION_X 0x0FF512EE
#define COMPRESSION_CAB 0x4643534D

inline uint32_t swap_u32(uint32_t val) {
    return ((val & 0xFF000000) >> 24) | ((val & 0x00FF0000) >> 8) | ((val & 0x0000FF00) << 8) | ((val & 0x000000FF) << 24);
}
inline uint64_t swap_u64(uint64_t val) {
    return ((val & 0xFF00000000000000ULL) >> 56) | ((val & 0x00FF000000000000ULL) >> 40) |
        ((val & 0x0000FF0000000000ULL) >> 24) | ((val & 0x000000FF00000000ULL) >> 8) |
        ((val & 0x00000000FF000000ULL) << 8) | ((val & 0x0000000000FF0000ULL) << 24) |
        ((val & 0x000000000000FF00ULL) << 40) | ((val & 0x00000000000000FFULL) << 56);
}
inline uint16_t swap_u16(uint16_t val) { return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8); }

struct XCompressHeader {
    uint32_t identifier, contextFlags, flags, windowSize, compressionPartitionSize;
    uint16_t version, reserved;
    uint64_t uncompressedSize, compressedSize;
    uint32_t uncompressedBlockSize, compressedBlockSizeMax;
};

class MemoryStream {
public:
    std::vector<uint8_t> data;
    size_t position = 0;
    size_t write(const void* buffer, size_t bytes) {
        if (!bytes) return 0;
        if (position + bytes > data.size()) data.resize(position + bytes);
        memcpy(data.data() + position, buffer, bytes);
        return position += bytes, bytes;
    }
    size_t read(void* buffer, size_t bytes) {
        if (position >= data.size() || !bytes) return 0;
        bytes = (std::min)(bytes, data.size() - position);
        memcpy(buffer, data.data() + position, bytes);
        return position += bytes, bytes;
    }
    void seek(long offset, int seektype) {
        position = seektype == SEEK_SET ? offset : seektype == SEEK_CUR ? position + offset : data.size() + offset;
    }
    size_t tell() const { return position; }
    size_t size() const { return data.size(); }
};

class ReadMemoryStream {
public:
    const uint8_t* data;
    size_t dataSize, position = 0;
    ReadMemoryStream(const uint8_t* d, size_t size) : data(d), dataSize(size) {}
    int read(void* buffer, int bytes) {
        uint16_t size;
        if (position + sizeof(uint16_t) > dataSize) return 0;
        memcpy(&size, data + position, sizeof(uint16_t));
        position += sizeof(uint16_t);
        size = swap_u16(size);
        if ((size & 0xFF00) == 0xFF00) {
            position++;
            if (position + sizeof(uint16_t) > dataSize) return 0;
            memcpy(&size, data + position, sizeof(uint16_t));
            position += sizeof(uint16_t);
            size = swap_u16(size);
        }
        if (position + size > dataSize) return 0;
        memcpy(buffer, data + position, size);
        return position += size, size;
    }
};

int mspack_read(mspack_file* file, void* buffer, int bytes) { return ((ReadMemoryStream*)file)->read(buffer, bytes); }
int mspack_write(mspack_file* file, void* buffer, int bytes) { return (int)((MemoryStream*)file)->write(buffer, bytes); }
void* mspack_alloc(mspack_system* self, size_t bytes) { return malloc(bytes); }
void mspack_free(void* ptr) { free(ptr); }
void mspack_copy(void* src, void* dst, size_t bytes) { memcpy(dst, src, bytes); }

mspack_system mspack_sys = { nullptr, nullptr, mspack_read, mspack_write, nullptr, nullptr, nullptr, mspack_alloc, mspack_free, mspack_copy };

namespace CAB {
    FNALLOC(fdiAlloc) { return operator new(cb); }
    FNFREE(fdiFree) { operator delete(pv); }
    FNOPEN(fdiOpen) { MemoryStream* s; (void)sscanf(pszFile, "%p", &s); return (INT_PTR)s; }
    FNREAD(fdiRead) { return (UINT)((MemoryStream*)hf)->read(pv, cb); }
    FNWRITE(fdiWrite) { return (UINT)((MemoryStream*)hf)->write(pv, cb); }
    FNCLOSE(fdiClose) { return 0; }
    FNSEEK(fdiSeek) { auto s = (MemoryStream*)hf; s->seek(dist, seektype); return (long)s->tell(); }
    FNFDINOTIFY(fdiNotify) { return fdint == fdintCOPY_FILE ? (INT_PTR)pfdin->pv : 0; }
    FNFCIFILEPLACED(fciFilePlaced) { return 0; }
    FNFCIALLOC(fciAlloc) { return fdiAlloc(cb); }
    FNFCIFREE(fciFree) { fdiFree(memory); }
    FNFCIOPEN(fciOpen) { return fdiOpen(pszFile, oflag, pmode); }
    FNFCIREAD(fciRead) { return fdiRead(hf, memory, cb); }
    FNFCIWRITE(fciWrite) { return fdiWrite(hf, memory, cb); }
    FNFCICLOSE(fciClose) { return fdiClose(hf); }
    FNFCISEEK(fciSeek) { return fdiSeek(hf, dist, seektype); }
    FNFCIDELETE(fciDelete) { MemoryStream* s; (void)sscanf(pszFile, "%p", &s); delete s; return 0; }
    FNFCIGETTEMPFILE(fciGetTempFile) { auto s = new MemoryStream(); sprintf(pszTempName, "%p", s); return TRUE; }
    FNFCIGETNEXTCABINET(fciGetNextCabinet) { return FALSE; }
    FNFCISTATUS(fciStatus) { return 0; }
    FNFCIGETOPENINFO(fciGetOpenInfo) { return fdiOpen(pszName, 0, 0); }
}

bool checkSignature(uint32_t s) { return s == COMPRESSION_X || s == COMPRESSION_CAB || swap_u32(s) == COMPRESSION_X || s == 0xEE12F50F; }

bool decompressXCompress(const std::vector<uint8_t>& inputData, std::vector<uint8_t>& outputData) {
    if (inputData.size() < sizeof(XCompressHeader)) return false;
    auto h = (const XCompressHeader*)inputData.data();
    if (h->identifier != COMPRESSION_X && swap_u32(h->identifier) != COMPRESSION_X && h->identifier != 0xEE12F50F) return false;
    
    bool isLittleEndian = (h->identifier == 0xEE12F50F);
    uint32_t windowSize = isLittleEndian ? swap_u32(h->windowSize) : h->windowSize;
    uint32_t cbs = isLittleEndian ? swap_u32(h->compressedBlockSizeMax) : h->compressedBlockSizeMax;
    uint64_t us = isLittleEndian ? swap_u64(h->uncompressedSize) : h->uncompressedSize;
    uint32_t ubs = isLittleEndian ? swap_u32(h->uncompressedBlockSize) : h->uncompressedBlockSize;
    
    int ws = 0;
    if (windowSize > 0) {
        uint32_t temp = windowSize;
        while ((temp & 0x1) == 0) {
            ++ws;
            temp >>= 1;
        }
    }
    if (ws == 0 || ws > 21) ws = 17;
    
    auto src = inputData.data() + sizeof(XCompressHeader);
    MemoryStream dst;
    
    while (dst.size() < us && src < inputData.data() + inputData.size()) {
        if (src + 4 > inputData.data() + inputData.size()) break;
        uint32_t cs = swap_u32(*(uint32_t*)src);
        src += 4;
        if (src + cs > inputData.data() + inputData.size()) break;
        
        size_t end_offset = src + cs - inputData.data();
        ReadMemoryStream srcStream(src, cs);
        size_t uncompressed_block_size = (std::min)((size_t)ubs, (size_t)(us - dst.size()));
        
        auto lzx = lzxd_init(&mspack_sys, (mspack_file*)&srcStream, (mspack_file*)&dst, ws, 0, cbs, uncompressed_block_size, 0);
        if (!lzx) return false;
        if (lzxd_decompress(lzx, uncompressed_block_size) != MSPACK_ERR_OK) { lzxd_free(lzx); return false; }
        lzxd_free(lzx);
        
        src = inputData.data() + end_offset;
    }
    outputData = std::move(dst.data);
    return true;
}

bool decompressCAB(const std::vector<uint8_t>& inputData, std::vector<uint8_t>& outputData) {
    MemoryStream src, dst;
    src.data = inputData;
    char cab[1]{}, path[24]{};
    sprintf(path, "%p", &src);
    ERF erf{};
    auto fdi = FDICreate(CAB::fdiAlloc, CAB::fdiFree, CAB::fdiOpen, CAB::fdiRead, CAB::fdiWrite, CAB::fdiClose, CAB::fdiSeek, cpuUNKNOWN, &erf);
    FDICopy(fdi, cab, path, 0, CAB::fdiNotify, nullptr, &dst);
    FDIDestroy(fdi);
    outputData = std::move(dst.data);
    return true;
}

bool compressCAB(const std::vector<uint8_t>& inputData, std::vector<uint8_t>& outputData, const char* fileName, int ws = 17) {
    MemoryStream src, dst;
    src.data = inputData;
    CCAB ccab{};
    sprintf(ccab.szCabPath, "%p", &dst);
    ERF erf{};
    auto fci = FCICreate(&erf, CAB::fciFilePlaced, CAB::fciAlloc, CAB::fciFree, CAB::fciOpen, CAB::fciRead, CAB::fciWrite, CAB::fciClose, CAB::fciSeek, CAB::fciDelete, CAB::fciGetTempFile, &ccab, nullptr);
    if (!fci) return false;
    char sf[24]{};
    sprintf(sf, "%p", &src);
    auto r = FCIAddFile(fci, sf, (LPSTR)fileName, FALSE, CAB::fciGetNextCabinet, CAB::fciStatus, CAB::fciGetOpenInfo, TCOMPfromLZXWindow(ws));
    r = r && FCIFlushCabinet(fci, FALSE, CAB::fciGetNextCabinet, CAB::fciStatus);
    FCIDestroy(fci);
    if (!r) return false;
    outputData = std::move(dst.data);
    return true;
}

bool compressXCompress(const std::vector<uint8_t>& inputData, std::vector<uint8_t>& outputData, const char* fileName) {
    std::vector<uint8_t> cab;
    if (!compressCAB(inputData, cab, fileName, 17)) return false;
    MemoryStream dst;
    auto hp = dst.tell();
    XCompressHeader h{};
    dst.write(&h, sizeof(h));
    uint32_t d = 0;
    dst.write(&d, 4);
    auto dp = cab.data();
    auto pos = *(uint32_t*)(dp + 0x24);
    auto cnt = *(uint16_t*)(dp + 0x28);
    dp += pos;
    for (size_t i = 0; i < cnt; i++) {
        dp += 4;
        auto cs = *(uint16_t*)dp; dp += 2;
        auto us = *(uint16_t*)dp; dp += 2;
        if (us != 0x8000) {
            uint8_t m = 0xFF;
            dst.write(&m, 1);
            auto sw = swap_u16(us);
            dst.write(&sw, 2);
        }
        auto swc = swap_u16(cs);
        dst.write(&swc, 2);
        dst.write(dp, cs);
        dp += cs;
    }
    uint8_t n[5]{};
    dst.write(n, 5);
    auto ep = dst.tell();
    h.identifier = swap_u32(COMPRESSION_X);
    h.version = swap_u32(0x1030000);
    h.windowSize = swap_u32(1 << 17);
    h.compressionPartitionSize = swap_u32(0x80000);
    h.uncompressedSize = swap_u64(inputData.size());
    h.compressedSize = swap_u64(ep - (hp + sizeof(h)));
    h.uncompressedBlockSize = swap_u32((uint32_t)inputData.size());
    h.compressedBlockSizeMax = swap_u32((uint32_t)(ep - (hp + sizeof(h) + 4)));
    dst.seek((long)hp, SEEK_SET);
    dst.write(&h, sizeof(h));
    dst.write(&h.compressedBlockSizeMax, 4);
    outputData = std::move(dst.data);
    return true;
}

std::string getFilename(const std::string& p) { auto pos = p.find_last_of("/\\"); return pos == std::string::npos ? p : p.substr(pos + 1); }
std::string getDirectory(const std::string& p) { auto pos = p.find_last_of("/\\"); return pos == std::string::npos ? "" : p.substr(0, pos); }
std::string getRelativePath(const std::string& full, const std::string& base) {
    if (full.find(base) == 0) {
        auto r = full.substr(base.length());
        if (!r.empty() && (r[0] == '/' || r[0] == '\\')) r = r.substr(1);
        return r;
    }
    return full;
}

bool compressFile(const std::string& path, uint32_t type, std::string& outFilename) {
    std::ifstream inf(path, std::ios::binary);
    if (!inf) return false;
    uint32_t sig;
    inf.read((char*)&sig, 4);
    if (checkSignature(sig)) {
        outFilename = "Already compressed! Skipping";
        return false;
    }
    inf.seekg(0);
    std::vector<uint8_t> in((std::istreambuf_iterator<char>(inf)), std::istreambuf_iterator<char>());
    inf.close();
    std::vector<uint8_t> out;
    auto fn = getFilename(path);
    bool ok = type == COMPRESSION_X ? compressXCompress(in, out, fn.c_str()) : type == COMPRESSION_CAB ? compressCAB(in, out, fn.c_str()) : false;
    if (!ok) return false;
    auto tmp = path + ".tmp";
    std::ofstream outf(tmp, std::ios::binary);
    if (!outf) return false;
    outf.write((char*)out.data(), out.size());
    outf.close();
    if (remove(path.c_str()) != 0) { remove(tmp.c_str()); return false; }
    if (rename(tmp.c_str(), path.c_str()) != 0) return false;
    outFilename = fn;
    return true;
}

bool decompressFile(const std::string& path, std::string& outFilename) {
    std::ifstream inf(path, std::ios::binary);
    if (!inf) return false;
    uint32_t sig;
    inf.read((char*)&sig, 4);
    inf.seekg(0);
    if (!checkSignature(sig)) return false;
    std::vector<uint8_t> in((std::istreambuf_iterator<char>(inf)), std::istreambuf_iterator<char>());
    inf.close();
    std::vector<uint8_t> out;
    bool ok = sig == COMPRESSION_CAB ? decompressCAB(in, out) : (sig == COMPRESSION_X || swap_u32(sig) == COMPRESSION_X || sig == 0xEE12F50F) ? decompressXCompress(in, out) : false;
    if (!ok) return false;
    auto tmp = path + ".tmp";
    std::ofstream outf(tmp, std::ios::binary);
    if (!outf) return false;
    outf.write((char*)out.data(), out.size());
    outf.close();
    if (remove(path.c_str()) != 0) { remove(tmp.c_str()); return false; }
    if (rename(tmp.c_str(), path.c_str()) != 0) return false;
    outFilename = getFilename(path);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 0;
    std::string arg = argv[1];
    bool compress = false;
    uint32_t type;
    if (arg == "-xcompress") compress = true, type = COMPRESSION_X;
    else if (arg == "-genscompress") compress = true, type = COMPRESSION_CAB;
    else if (arg != "-decompress") return 0;
    std::string base;
    try { base = fs::current_path().string(); }
    catch (...) { base = ""; }
    std::map<std::string, std::vector<std::string>> dirs;
    for (int i = 2; i < argc; i++) {
        try { std::string f = argv[i]; dirs[getDirectory(f)].push_back(f); }
        catch (...) {}
    }
    std::string lastDir;
    for (auto& [dir, files] : dirs) {
        auto d = getRelativePath(dir, base);
        if (d.empty()) d = ".";
        if (d != lastDir) {
            std::cout << "\nDirectory: " << d << "\n" << std::endl;
            lastDir = d;
        }
        for (const auto& f : files) {
            auto fn = getFilename(f);
            std::string result;
            bool success = compress ? compressFile(f, type, result) : decompressFile(f, result);
            if (success) {
                std::cout << fn << " => " << result << std::endl;
            } else if (!result.empty()) {
                std::cout << result << ": " << fn << std::endl;
            }
        }
    }
    return 0;
}
