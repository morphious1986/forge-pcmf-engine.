#include "pcmf_json.h"
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string_view>

namespace pcmf {

std::string escape(const std::string&input){
    static constexpr char hexd[]="0123456789abcdef";
    std::string r="\"";
    for(unsigned char c:input){
        if(c=='"'||c=='\\'){r+='\\';r+=(char)c;}
        else if(c=='\n')r+="\\n";
        else if(c=='\r')r+="\\r";
        else if(c=='\t')r+="\\t";
        else if(c=='\b')r+="\\b";
        else if(c=='\f')r+="\\f";
        else if(c<32){r+="\\u00";r+=hexd[c>>4];r+=hexd[c&15];}
        else r+=(char)c;
    }
    return r+"\"";
}

static std::string dump_(const J&v){
    if(v.t==J::Null)return "null";
    if(v.t==J::Bool)return v.b?"true":"false";
    if(v.t==J::Num)return v.s;
    if(v.t==J::Str)return escape(v.s);
    std::string s=v.t==J::Arr?"[":"{";
    if(v.t==J::Arr)for(const auto&x:v.a){if(s.size()>1)s+=',';s+=dump_(x);}
    else for(const auto&[k,x]:v.o){if(s.size()>1)s+=',';s+=escape(k)+":"+dump_(x);}
    return s+(v.t==J::Arr?"]":"}");
}
std::string dump(const J&v){return dump_(v);}

struct Parser {
    std::string_view src;size_t p=0;int depth=0;
    explicit Parser(std::string_view s):src(s){}
    void ws(){while(p<src.size()&&(src[p]==' '||src[p]=='\n'||src[p]=='\r'||src[p]=='\t'))p++;}
    void need(char c){if(p>=src.size()||src[p++]!=c)throw std::runtime_error("JSON_SYNTAX");}
    static int hx(char c){
        if(c>='0'&&c<='9')return c-'0';
        if(c>='a'&&c<='f')return c-'a'+10;
        if(c>='A'&&c<='F')return c-'A'+10;
        throw std::runtime_error("JSON_HEX");
    }
    uint32_t cp(){uint32_t n=0;for(int i=0;i<4;i++){if(p>=src.size())throw std::runtime_error("JSON_UNICODE");n=(n<<4)|hx(src[p++]);}return n;}
    static void utf8(std::string&out,uint32_t c){
        if(c<=0x7f)out+=(char)c;
        else if(c<=0x7ff){out+=(char)(0xc0|(c>>6));out+=(char)(0x80|(c&63));}
        else if(c<=0xffff){out+=(char)(0xe0|(c>>12));out+=(char)(0x80|((c>>6)&63));out+=(char)(0x80|(c&63));}
        else{out+=(char)(0xf0|(c>>18));out+=(char)(0x80|((c>>12)&63));out+=(char)(0x80|((c>>6)&63));out+=(char)(0x80|(c&63));}
    }
    std::string string(){
        need('"');std::string r;
        while(p<src.size()){
            unsigned char c=src[p++];
            if(c=='"')return r;
            if(c<32)throw std::runtime_error("JSON_CONTROL");
            if(c!='\\'){r+=(char)c;continue;}
            if(p==src.size())throw std::runtime_error("JSON_ESCAPE");
            char e=src[p++];
            if(e=='"'||e=='\\'||e=='/')r+=e;
            else if(e=='n')r+='\n';
            else if(e=='r')r+='\r';
            else if(e=='t')r+='\t';
            else if(e=='b')r+='\b';
            else if(e=='f')r+='\f';
            else if(e=='u'){
                uint32_t c1=cp();
                if(c1>=0xd800&&c1<=0xdbff){
                    need('\\');need('u');uint32_t c2=cp();
                    if(c2<0xdc00||c2>0xdfff)throw std::runtime_error("JSON_SURROGATE");
                    c1=0x10000+((c1-0xd800)<<10)+(c2-0xdc00);
                }else if(c1>=0xdc00&&c1<=0xdfff)throw std::runtime_error("JSON_SURROGATE");
                utf8(r,c1);
            }else throw std::runtime_error("JSON_ESCAPE");
        }
        throw std::runtime_error("JSON_STRING_EOF");
    }
    J value(){
        if(++depth>20)throw std::runtime_error("JSON_DEPTH");
        ws();if(p>=src.size())throw std::runtime_error("JSON_EOF");
        J r;char c=src[p];
        if(c=='"')r=J::string(string());
        else if(c=='{'){
            p++;r=J::object();ws();
            if(p<src.size()&&src[p]=='}')p++;
            else for(;;){
                ws();auto k=string();ws();need(':');
                if(r.o.count(k))throw std::runtime_error("JSON_DUPLICATE_KEY");
                r.o.emplace(std::move(k),value());ws();
                if(p<src.size()&&src[p]=='}'){p++;break;}
                need(',');
            }
        }else if(c=='['){
            p++;r=J::array();ws();
            if(p<src.size()&&src[p]==']')p++;
            else for(;;){
                r.a.push_back(value());ws();
                if(p<src.size()&&src[p]==']'){p++;break;}
                need(',');
            }
        }else if(src.substr(p,4)=="true"){p+=4;r=J::boolean(true);}
        else if(src.substr(p,5)=="false"){p+=5;r=J::boolean(false);}
        else if(src.substr(p,4)=="null"){p+=4;r=J();}
        else if(c=='-'||(c>='0'&&c<='9')){
            size_t start=p;if(src[p]=='-')p++;
            if(p>=src.size())throw std::runtime_error("JSON_NUMBER");
            if(src[p]=='0')p++;
            else{
                if(src[p]<'1'||src[p]>'9')throw std::runtime_error("JSON_NUMBER");
                while(p<src.size()&&isdigit((unsigned char)src[p]))p++;
            }
            if(p<src.size()&&src[p]=='.'){p++;if(p==src.size()||!isdigit((unsigned char)src[p]))throw std::runtime_error("JSON_NUMBER");while(p<src.size()&&isdigit((unsigned char)src[p]))p++;}
            if(p<src.size()&&(src[p]=='e'||src[p]=='E')){p++;if(p<src.size()&&(src[p]=='+'||src[p]=='-'))p++;if(p==src.size()||!isdigit((unsigned char)src[p]))throw std::runtime_error("JSON_NUMBER");while(p<src.size()&&isdigit((unsigned char)src[p]))p++;}
            r.t=J::Num;r.s=std::string(src.substr(start,p-start));
        }else throw std::runtime_error("JSON_TOKEN");
        depth--;return r;
    }
    J whole(){J v=value();ws();if(p!=src.size())throw std::runtime_error("JSON_TRAILING");return v;}
};

J parse(const std::string&s){return Parser(s).whole();}

} // namespace pcmf
