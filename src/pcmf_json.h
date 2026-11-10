#ifndef PCMF_JSON_H
#define PCMF_JSON_H
/*
 * PCMF R14 canonical JSON. Extracted verbatim (behavior-identical) from the
 * verified R10 writer's canonical parser/serializer so historical R55 v2
 * ledgers, canonical dumps, and event-id/hash derivations remain exactly
 * reproducible. Canonical dump: object keys in std::map order, no spaces,
 * standard escaping; parse rejects duplicate keys, depth > 20, raw control
 * characters, lone surrogates, and trailing data.
 */
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace pcmf {

struct J {
    enum Type { Null, Bool, Num, Str, Arr, Obj } t=Null;
    std::string s;
    bool b=false;
    std::vector<J> a;
    std::map<std::string,J> o;
    static J string(std::string v){J r;r.t=Str;r.s=std::move(v);return r;}
    static J number(long long v){J r;r.t=Num;r.s=std::to_string(v);return r;}
    static J boolean(bool v){J r;r.t=Bool;r.b=v;return r;}
    static J array(){J r;r.t=Arr;return r;}
    static J object(){J r;r.t=Obj;return r;}
    J& operator[](const std::string&k){if(t!=Obj)throw std::runtime_error("NOT_OBJECT");return o[k];}
    const J& at(const std::string&k) const {
        if(t!=Obj)throw std::runtime_error("NOT_OBJECT");
        auto i=o.find(k);if(i==o.end())throw std::runtime_error("MISSING_FIELD");return i->second;
    }
    bool has(const std::string&k) const {return t==Obj&&o.count(k)!=0;}
    std::string as_string()const{if(t!=Str)throw std::runtime_error("NOT_STRING");return s;}
    long long as_int()const{
        if(t!=Num||s.empty())throw std::runtime_error("NOT_NUMBER");
        std::size_t p=0;long long n=std::stoll(s,&p);
        if(p!=s.size())throw std::runtime_error("INVALID_NUMBER");
        return n;
    }
};

std::string escape(const std::string&input);
std::string dump(const J&v);
J parse(const std::string&s);

} // namespace pcmf
#endif
