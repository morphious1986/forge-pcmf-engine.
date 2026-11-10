/*
 * PCMF Living Memory R14 - native local service daemon (pcmf-serve).
 *
 * Binds an AF_UNIX socket (0600, private directory) - no network sockets,
 * no interception of any other program's traffic, no ChatGPT hook. Every
 * request is authenticated and dispatched through Engine::request(), the
 * same single entry point used by the local CLI, so daemon and direct mode
 * have identical authorization and replay semantics.
 */
#include "pcmf_engine.h"
#include "pcmf_util.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static volatile std::sig_atomic_t g_stop=0;
static std::string g_socket_path;

static void on_signal(int){g_stop=1;}

static std::string default_socket(){
    const char*rt=getenv("XDG_RUNTIME_DIR");
    if(rt&&*rt)return std::string(rt)+"/pcmf/pcmf.sock";
    const char*home=getenv("HOME");
    if(home&&*home)return std::string(home)+"/.local/run/pcmf/pcmf.sock";
    return std::string();
}

static void write_service_state(const std::string&root,const std::string&socket_path){
    try{
        pcmf::Engine eng(root);
        /* touch state/service.json via engine root (private) */
        const std::string dir=root+"/state";
        pcmf::J st=pcmf::J::object();
        st["pid"]=pcmf::J::number((long long)getpid());
        st["started_at"]=pcmf::J::string(pcmf::format_time(pcmf::now_epoch()));
        st["socket"]=pcmf::J::string(socket_path);
        st["version"]=pcmf::J::string(PCMF_VERSION_STRING);
        st["canonical_writer"]=pcmf::J::string(PCMF_CANONICAL_HOLD);
        pcmf::atomic_replace(dir,"service.json",pcmf::dump(st)+"\n");
    }catch(const std::exception&){/* best-effort */}
}

int main(int argc,char**argv){
    std::signal(SIGPIPE,SIG_IGN);
    {   /* no SA_RESTART: accept() must observe the stop flag */
        struct sigaction sa{};
        sa.sa_handler=on_signal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags=0;
        sigaction(SIGTERM,&sa,nullptr);
        sigaction(SIGINT,&sa,nullptr);
    }

    std::string root,socket_path=default_socket();
    for(int i=1;i<argc;i++){
        const std::string a=argv[i];
        if(a=="--root"&&i+1<argc)root=argv[++i];
        else if(a=="--socket"&&i+1<argc)socket_path=argv[++i];
        else if(a=="--foreground"){/* daemon always runs foreground */}
        else{
            std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
                "\"reason\":\"ARGS_NOT_ACCEPTED\",\"canonical_writer\":\"%s\"}\n",
                PCMF_CANONICAL_HOLD);
            return 2;
        }
    }
    if(root.empty()&&!pcmf::resolve_default_root(root)){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"NO_DATA_ROOT_CONFIGURED\",\"canonical_writer\":\"%s\"}\n",
            PCMF_CANONICAL_HOLD);
        return 2;
    }
    if(socket_path.empty()){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"NO_SOCKET_PATH\",\"canonical_writer\":\"%s\"}\n",
            PCMF_CANONICAL_HOLD);
        return 2;
    }
    if(pcmf::contains_component_dotdot(socket_path)){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"SOCKET_PATH_INVALID\",\"canonical_writer\":\"%s\"}\n",
            PCMF_CANONICAL_HOLD);
        return 2;
    }

    std::unique_ptr<pcmf::Engine> eng;
    try{
        eng=std::make_unique<pcmf::Engine>(root);
    }catch(const std::exception&e){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"ROOT_OPEN_DENIED\",\"detail\":\"%s\","
            "\"canonical_writer\":\"%s\"}\n",e.what(),PCMF_CANONICAL_HOLD);
        return 2;
    }

    /* socket directory: private */
    {
        const std::string dir=pcmf::path_basename(socket_path);
        const size_t slash=socket_path.find_last_of('/');
        const std::string parent=socket_path.substr(0,slash);
        pcmf::ensure_dir(parent,0700);
        pcmf::require_private_dir(parent);
        (void)dir;
    }
    // Protect unrelated files and live PCMF socket servers from removal.
    if(socket_path.size()>=sizeof(sockaddr_un{}.sun_path)){
        std::fprintf(stderr,"BLOCKED_SOCKET_PATH_TOO_LONG\n");
        return 2;
    }
    struct stat existing{};
    if(lstat(socket_path.c_str(),&existing)==0){
        if(!S_ISSOCK(existing.st_mode)||existing.st_uid!=geteuid()){
            std::fprintf(stderr,"BLOCKED_SOCKET_PATH_NOT_OWNED_SOCKET\n");
            return 2;
        }
        int probe=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
        if(probe<0){
            std::fprintf(stderr,"BLOCKED_SOCKET_PROBE_CREATE\n");
            return 2;
        }
        sockaddr_un candidate{};
        candidate.sun_family=AF_UNIX;
        std::memcpy(candidate.sun_path,socket_path.c_str(),socket_path.size());
        if(connect(probe,(const sockaddr*)&candidate,sizeof candidate)==0){
            close(probe);
            std::fprintf(stderr,"BLOCKED_SOCKET_ALREADY_ACTIVE\n");
            return 2;
        }
        const int connection_error=errno;
        close(probe);
        if(connection_error!=ECONNREFUSED ||
           unlink(socket_path.c_str())!=0){
            std::fprintf(stderr,"BLOCKED_SOCKET_NOT_STALE\n");
            return 2;
        }
    }else if(errno!=ENOENT){
        std::fprintf(stderr,"BLOCKED_SOCKET_PATH_LSTAT\n");
        return 2;
    }
    const int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"SOCKET_CREATE_FAILED\",\"canonical_writer\":\"%s\"}\n",
            PCMF_CANONICAL_HOLD);
        return 2;
    }
    sockaddr_un addr{};
    addr.sun_family=AF_UNIX;
    if(socket_path.size()>=sizeof addr.sun_path){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"SOCKET_PATH_TOO_LONG\",\"canonical_writer\":\"%s\"}\n",
            PCMF_CANONICAL_HOLD);
        return 2;
    }
    std::memcpy(addr.sun_path,socket_path.c_str(),socket_path.size());
    if(bind(fd,(const sockaddr*)&addr,sizeof addr)!=0||listen(fd,16)!=0||
       chmod(socket_path.c_str(),0600)!=0){
        std::fprintf(stderr,"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
            "\"reason\":\"SOCKET_BIND_FAILED\",\"canonical_writer\":\"%s\"}\n",
            PCMF_CANONICAL_HOLD);
        return 2;
    }
    g_socket_path=socket_path;
    write_service_state(root,socket_path);
    std::printf("{\"status\":\"SERVING\",\"socket\":\"%s\",\"version\":\"%s\","
        "\"canonical_writer\":\"%s\"}\n",socket_path.c_str(),PCMF_VERSION_STRING,
        PCMF_CANONICAL_HOLD);
    std::fflush(stdout);

    std::string in;
    char buf[2048];
    while(!g_stop){
        const int conn=accept(fd,nullptr,nullptr);
        if(conn<0){
            if(g_stop)break;
            continue;
        }
        std::string frame;
        bool capped=false;
        for(;;){
            const ssize_t n=read(conn,buf,sizeof buf);
            if(n<=0)break;
            frame.append(buf,(size_t)n);
            if(frame.size()>8192+132+8){capped=true;break;}
            if(frame.size()>=2&&frame[frame.size()-1]=='\n'&&
               frame[frame.size()-2]=='\n')break; /* some clients send CRLF-free double \n */
            /* frame is two lines: payload\nsig\n - stop after second newline */
            size_t first=frame.find('\n');
            if(first!=std::string::npos){
                size_t second=frame.find('\n',first+1);
                if(second!=std::string::npos)break;
            }
        }
        std::string response;
        if(capped){
            response=std::string("{\"v\":\"")+PCMF_PROTOCOL+
                "\",\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
                "\"reason\":\"FRAME_TOO_LARGE\",\"canonical_writer\":\""+
                PCMF_CANONICAL_HOLD+"\",\"engine\":\""+PCMF_VERSION_STRING+"\"}";
        }else{
            size_t nl=frame.find('\n');
            if(nl==std::string::npos){
                response=std::string("{\"v\":\"")+PCMF_PROTOCOL+
                    "\",\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
                    "\"reason\":\"FRAME_STRUCTURE\",\"canonical_writer\":\""+
                    PCMF_CANONICAL_HOLD+"\",\"engine\":\""+PCMF_VERSION_STRING+"\"}";
            }else{
                std::string payload=frame.substr(0,nl);
                std::string rest=frame.substr(nl+1);
                size_t nl2=rest.find('\n');
                std::string sig=nl2==std::string::npos?rest:rest.substr(0,nl2);
                response=eng->request(payload,sig);
            }
        }
        response+='\n';
        size_t off=0;
        while(off<response.size()){
            const ssize_t n=write(conn,response.data()+off,response.size()-off);
            if(n<0){if(errno==EINTR)continue;break;}
            off+=(size_t)n;
        }
        close(conn);
    }
    close(fd);
    unlink(socket_path.c_str());
    /* clear service state */
    try{
        pcmf::Engine eng(root);
        std::string sj=eng.root()+"/state/service.json";
        unlink(sj.c_str());
    }catch(const std::exception&){}
    std::printf("{\"status\":\"STOPPED\",\"canonical_writer\":\"%s\"}\n",
        PCMF_CANONICAL_HOLD);
    return 0;
}
