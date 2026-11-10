#define _POSIX_C_SOURCE 200809L
#include "pcmf_util.h"
#include "pcmf_sha256.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace pcmf {

long long now_epoch(){return (long long)time(nullptr);}

std::string format_time(long long epoch){
    time_t t=(time_t)epoch;
    if((long long)t!=epoch)die("EPOCH_RANGE");
    struct tm out{};
    if(!gmtime_r(&t,&out))die("GMTIME");
    char b[48];
    if(!strftime(b,sizeof b,"%Y-%m-%dT%H:%M:%S+00:00",&out))die("TIMESTAMP");
    return b;
}

bool valid_epoch_string(const std::string&s,long long&out){
    if(s.empty()||s.size()>18)return false;
    for(char c:s)if(!isdigit((unsigned char)c))return false;
    errno=0;char*stop=nullptr;
    long long v=strtoll(s.c_str(),&stop,10);
    if(errno!=0||!stop||*stop!='\0'||v<1)return false;
    out=v;return true;
}

/* days-from-civil (proleptic Gregorian), public-domain algorithm. */
static long long days_from_civil(long long y,unsigned m,unsigned d){
    y-=m<=2;
    const long long era=(y>=0?y:y-399)/400;
    const unsigned yoe=(unsigned)(y-era*400);
    const unsigned doy=(153u*(m+(m>2?-3:9))+2)/5+d-1;
    const unsigned doe=yoe*365+yoe/4-yoe/100+doy;
    return era*146097ll+(long long)doe-719468ll;
}

bool epoch_from_utc(const std::string&ts,long long&out){
    /* Expect engine format: 2026-10-24T12:34:56+00:00 (at least the first 19 chars) */
    if(ts.size()<19)return false;
    int Y=0,Mo=0,D=0,h=0,mi=0,se=0;
    if(std::sscanf(ts.c_str(),"%4d-%2d-%2dT%2d:%2d:%2d",
                   &Y,&Mo,&D,&h,&mi,&se)!=6)return false;
    if(Mo<1||Mo>12||D<1||D>31||h<0||h>23||mi<0||mi>59||se<0||se>60)return false;
    out=days_from_civil(Y,(unsigned)Mo,(unsigned)D)*86400+h*3600+mi*60+se;
    return true;
}

bool is_name(const std::string&s,size_t min,size_t max){
    if(s.size()<min||s.size()>max)return false;
    if(!isalpha((unsigned char)s[0]))return false;
    for(unsigned char c:s)if(!isalnum(c)&&c!='_')return false;
    return true;
}
bool is_hex(const std::string&s,size_t exact_bytes){
    if(s.size()!=exact_bytes*2)return false;
    for(char c:s)
        if(!isdigit((unsigned char)c)&&
           !(c>='a'&&c<='f')&&!(c>='A'&&c<='F'))return false;
    return true;
}
std::string lowered(const std::string&s){
    std::string r=s;
    std::transform(r.begin(),r.end(),r.begin(),
        [](unsigned char c){return (char)tolower(c);});
    return r;
}
bool name_has_reserved_identity(const std::string&client_id){
    const std::string l=lowered(client_id);
    if(l.find("chatgpt")!=std::string::npos)return true;
    if(l.find("openai")!=std::string::npos)return true;
    return false;
}

bool file_exists(const std::string&path){
    struct stat st{};
    return lstat(path.c_str(),&st)==0&&S_ISREG(st.st_mode);
}
bool dir_exists(const std::string&path){
    struct stat st{};
    return lstat(path.c_str(),&st)==0&&S_ISDIR(st.st_mode);
}

std::string read_file_bounded(const std::string&path,size_t cap){
    int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)die("OPEN_READ_FAILED");
    std::string s;
    char buf[8192];
    for(;;){
        ssize_t n=read(fd,buf,sizeof buf);
        if(n<0){if(errno==EINTR)continue;close(fd);die("READ_FAILED");}
        if(n==0)break;
        if(s.size()+(size_t)n>cap){close(fd);die("SIZE_LIMIT");}
        s.append(buf,(size_t)n);
    }
    close(fd);
    return s;
}

void write_file_private(const std::string&path,const std::string&data){
    int fd=open(path.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)die("OPEN_WRITE_FAILED");
    size_t i=0;
    while(i<data.size()){
        ssize_t n=write(fd,data.data()+i,data.size()-i);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){close(fd);die("WRITE_FAILED");}
        i+=(size_t)n;
    }
    if(fsync(fd)!=0){close(fd);die("FSYNC_FAILED");}
    close(fd);
}

void atomic_replace(const std::string&dir,const std::string&name,
                    const std::string&data){
    int dfd=open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dfd<0)die("DIR_OPEN_FAILED");
    const std::string tmp="."+name+".tmp."+std::to_string((long long)getpid());
    int fd=openat(dfd,tmp.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){close(dfd);die("TEMP_CREATE_FAILED");}
    bool ok=true;
    size_t i=0;
    while(ok&&i<data.size()){
        ssize_t n=write(fd,data.data()+i,data.size()-i);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)ok=false;else i+=(size_t)n;
    }
    if(ok)ok=fsync(fd)==0;
    close(fd);
    if(ok)ok=renameat(dfd,tmp.c_str(),dfd,name.c_str())==0;
    else unlinkat(dfd,tmp.c_str(),0);
    if(ok)ok=fsync(dfd)==0;
    close(dfd);
    if(!ok)die("ATOMIC_REPLACE_FAILED");
}

void ensure_dir(const std::string&path,int mode){
    if(mkdir(path.c_str(),(mode_t)mode)!=0){
        if(errno!=EEXIST)die("MKDIR_FAILED");
    }
    /* If it already existed, leave modes as-is; require_private_dir enforces. */
}

void require_private_dir(const std::string&path){
    struct stat st{};
    if(stat(path.c_str(),&st)!=0)die("DIR_MISSING");
    if(!S_ISDIR(st.st_mode))die("NOT_A_DIRECTORY");
    if(st.st_uid!=geteuid())die("DIR_NOT_OWNED_BY_EUID");
    if((st.st_mode&077)!=0)die("DIR_NOT_PRIVATE");
}
void require_private_file(const std::string&path,size_t exact_size){
    struct stat st{};
    int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)die("FILE_OPEN_DENIED");
    bool ok=fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_uid==geteuid()
        &&(st.st_mode&077)==0;
    if(ok&&exact_size>0)ok=(size_t)st.st_size==exact_size;
    close(fd);
    if(!ok)die("FILE_NOT_PRIVATE_OR_WRONG_SIZE");
}

std::string path_basename(const std::string&p){
    auto pos=p.find_last_of('/');
    return pos==std::string::npos?p:p.substr(pos+1);
}
bool contains_component_dotdot(const std::string&p){
    size_t i=0;
    while(i<p.size()){
        size_t j=p.find('/',i);
        if(j==std::string::npos)j=p.size();
        if(j-i==2&&p[i]=='.'&&p[i+1]=='.')return true;
        i=j+1;
    }
    return false;
}
bool mkpath_absolute(std::string&out){
    char buf[4096];
    if(!realpath(out.c_str(),buf))return false;
    out=buf;
    if(out.empty()||out[0]!='/')return false;
    if(contains_component_dotdot(out))return false;
    return true;
}

std::string sha256_hex(const std::string&s){
    uint8_t d[32];pcmf_sha256(s.data(),s.size(),d);
    char hex[65];pcmf_to_hex(d,32,hex);
    return std::string(hex);
}
std::string hmac_hex(const std::string&key,const std::string&msg){
    uint8_t d[32];
    pcmf_hmac_sha256((const uint8_t*)key.data(),key.size(),msg.data(),msg.size(),d);
    char hex[65];pcmf_to_hex(d,32,hex);
    return std::string(hex);
}
std::string random_hex(size_t bytes){
    ensure(bytes>=1&&bytes<=64,"RANDOM_TOO_LARGE");
    std::string out;out.resize(bytes);
    uint8_t*buf=(uint8_t*)out.data();
    size_t got=0;
    while(got<bytes){
        ssize_t n=getrandom(buf+got,bytes-got,0);
        if(n<0){
            if(errno==EINTR)continue;
            /* Fallback: /dev/urandom */
            int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);
            if(fd<0)die("ENTROPY_UNAVAILABLE");
            while(got<bytes){
                ssize_t r=read(fd,buf+got,bytes-got);
                if(r<0){if(errno==EINTR)continue;close(fd);die("ENTROPY_READ_FAILED");}
                got+=(size_t)r;
            }
            close(fd);
            break;
        }
        got+=(size_t)n;
    }
    char hex[129];
    pcmf_to_hex(buf,bytes,hex);      /* encode BEFORE cleansing */
    cleanse(out);
    return std::string(hex,bytes*2);
}
void cleanse(std::string&s){
    volatile char*p=s.data();
    for(size_t i=0;i<s.size();i++)p[i]=0;
}

void FileLock::acquire(const std::string&p){
    path=p;
    fd=open(p.c_str(),O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)die("LOCK_DENIED");
    if(flock(fd,LOCK_EX)!=0){close(fd);fd=-1;die("LOCK_FAILED");}
}
void FileLock::release(){
    if(fd>=0){flock(fd,LOCK_UN);close(fd);fd=-1;}
}
FileLock::~FileLock(){release();}

std::string trim(const std::string&s){
    size_t a=0,b=s.size();
    while(a<b&&isspace((unsigned char)s[a]))a++;
    while(b>a&&isspace((unsigned char)s[b-1]))b--;
    return s.substr(a,b-a);
}
std::vector<std::string> split_lines(const std::string&s){
    std::vector<std::string> out;
    size_t start=0;
    while(start<=s.size()){
        size_t end=s.find('\n',start);
        if(end==std::string::npos){if(start<s.size())out.push_back(s.substr(start));break;}
        out.push_back(s.substr(start,end-start));
        start=end+1;
    }
    return out;
}

bool resolve_default_root(std::string&out){
    const char*env=std::getenv("PCMF_DATA_ROOT");
    if(env&&*env){out=env;return true;}
    const char*home=std::getenv("HOME");
    if(!home||!*home)return false;
    const std::string cfg=std::string(home)+"/.config/pcmf/pcmf.conf";
    if(!file_exists(cfg))return false;
    std::string bytes=read_file_bounded(cfg,65536);
    for(const auto&line:split_lines(bytes)){
        std::string l=trim(line);
        if(l.empty()||l[0]=='#')continue;
        auto eq=l.find('=');
        if(eq==std::string::npos)continue;
        if(trim(l.substr(0,eq))=="data_root"){
            std::string v=trim(l.substr(eq+1));
            if(!v.empty()){out=v;return true;}
        }
    }
    return false;
}

} // namespace pcmf
