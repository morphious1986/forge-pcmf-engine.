#ifndef PCMF_UTIL_H
#define PCMF_UTIL_H
/*
 * PCMF R14 shared utilities: bounded reads, atomic durable writes, locking,
 * secure key material, validation, time formatting. C++20.
 */
#include <cstdint>
#include <string>
#include <vector>

namespace pcmf {

/* ---------- errors ---------- */
struct Fail { std::string why; explicit Fail(std::string w):why(std::move(w)){} };
[[noreturn]] inline void die(const char*why){throw Fail(why);}
[[noreturn]] inline void die(std::string why){throw Fail(std::move(why));}
inline void ensure(bool ok,const char*why){if(!ok)throw Fail(why);}
inline void ensure(bool ok,std::string why){if(!ok)throw Fail(std::move(why));}

/* ---------- time ---------- */
long long now_epoch();
std::string format_time(long long epoch);          /* RFC3339 UTC */
bool valid_epoch_string(const std::string&s,long long&out);
/* Parses "YYYY-MM-DDTHH:MM:SS+00:00" (engine-produced UTC) to epoch seconds
 * using the days-from-civil algorithm; returns false on malformed input. */
bool epoch_from_utc(const std::string&ts,long long&out);

/* ---------- strings / validation ---------- */
bool is_name(const std::string&s,size_t min,size_t max);
bool is_hex(const std::string&s,size_t exact_bytes);
bool name_has_reserved_identity(const std::string&client_id);
/* Reserved: client ids must never impersonate ChatGPT/OpenAI identities;
 * "sol"-prefixed ids require the Sol integration to be explicitly enabled. */
std::string lowered(const std::string&s);

/* ---------- filesystem ---------- */
bool file_exists(const std::string&path);
bool dir_exists(const std::string&path);
std::string read_file_bounded(const std::string&path,size_t cap);
void write_file_private(const std::string&path,const std::string&data); /* 0600 */
void atomic_replace(const std::string&dir,const std::string&name,
                    const std::string&data);       /* tmp+fsync+rename+dirfsync */
void ensure_dir(const std::string&path,int mode);
void require_private_dir(const std::string&path);  /* owned by euid, mode 0700 */
void require_private_file(const std::string&path,size_t exact_size);
std::string path_basename(const std::string&p);
bool mkpath_absolute(std::string&out);             /* resolve to absolute, no ".." */

/* ---------- crypto helpers over pcmf_sha256 ---------- */
std::string sha256_hex(const std::string&s);
std::string hmac_hex(const std::string&key,const std::string&msg);
std::string random_hex(size_t bytes);              /* getrandom / urandom */
void cleanse(std::string&s);

/* ---------- lock ---------- */
struct FileLock {
    int fd=-1;std::string path;
    void acquire(const std::string&p);              /* open+LOCK_EX, creates 0600 */
    void release();
    ~FileLock();
};

/* ---------- misc ---------- */
std::string trim(const std::string&s);
std::vector<std::string> split_lines(const std::string&s);
bool contains_component_dotdot(const std::string&p);

/* Root resolution order: $PCMF_DATA_ROOT, then $HOME/.config/pcmf/pcmf.conf
 * (data_root=...). Returns false if none is configured. */
bool resolve_default_root(std::string&out);

} // namespace pcmf
#endif
