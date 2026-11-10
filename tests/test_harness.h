#ifndef PCMF_TEST_HARNESS_H
#define PCMF_TEST_HARNESS_H
/*
 * PCMF R14 native test harness: no Python, no Node, no external test
 * frameworks. Disposable synthetic roots under /tmp/pcmf-selftest-*.
 * Real memory is never touched: every root is created by the tests and
 * deleted afterwards.
 */
#include "pcmf_engine.h"
#include "pcmf_util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace test {

struct TestFail { std::string msg; };

static long long g_counter=0;

inline std::string fresh_root(const char*tag){
    char buf[256];
    std::snprintf(buf,sizeof buf,"/tmp/pcmf-selftest-%ld-%lld-%s",
        (long)getpid(),++g_counter,tag);
    return std::string(buf);
}

inline void remove_tree(const std::string&path){
    std::string cmd="rm -rf '"+path+"'";
    if(std::system(cmd.c_str())!=0){}
}

inline void check(bool ok,const std::string&msg){
    if(!ok)throw TestFail{msg};
}

inline bool contains(const std::string&hay,const std::string&needle){
    return hay.find(needle)!=std::string::npos;
}

/* ---------- process helper (exec, pipes, wait) ---------- */
struct ProcResult { int exit_code=0; std::string out; };

inline ProcResult run_process(const std::vector<std::string>&argv,
                              const std::string&input="",
                              const std::vector<std::string>&env_extra={},
                              const std::string&cwd=""){
    ProcResult r;
    int to[2],from[2];
    if(pipe(to)!=0)throw TestFail{"pipe"};
    if(pipe(from)!=0)throw TestFail{"pipe"};
    const pid_t pid=fork();
    if(pid<0)throw TestFail{"fork"};
    if(pid==0){
        dup2(to[0],STDIN_FILENO);dup2(from[1],STDOUT_FILENO);
        close(to[0]);close(to[1]);close(from[0]);close(from[1]);
        if(!cwd.empty())if(chdir(cwd.c_str())!=0)_exit(126);
        for(const auto&kv:env_extra){
            const auto eq=kv.find('=');
            if(eq==std::string::npos)continue;
            setenv(kv.substr(0,eq).c_str(),kv.substr(eq+1).c_str(),1);
        }
        std::vector<char*> a;
        for(const auto&x:argv)a.push_back(const_cast<char*>(x.c_str()));
        a.push_back(nullptr);
        execv(a[0],a.data());
        _exit(127);
    }
    close(to[0]);close(from[1]);
    if(!input.empty()){
        size_t off=0;
        while(off<input.size()){
            const ssize_t n=write(to[1],input.data()+off,input.size()-off);
            if(n<0){if(errno==EINTR)continue;break;}
            off+=(size_t)n;
        }
    }
    close(to[1]);
    char buf[4096];
    for(;;){
        const ssize_t n=read(from[0],buf,sizeof buf);
        if(n<0){if(errno==EINTR)continue;break;}
        if(n==0)break;
        r.out.append(buf,(size_t)n);
        if(r.out.size()>1000000)break;
    }
    close(from[0]);
    int status=0;
    if(waitpid(pid,&status,0)!=pid)throw TestFail{"waitpid"};
    r.exit_code=WIFEXITED(status)?WEXITSTATUS(status):-1;
    return r;
}

inline std::string bin_dir(int argc,char**argv){
    if(argc>1)return argv[argc-1]==nullptr?"":argv[1];
    const char*env=getenv("PCMF_BIN_DIR");
    if(env)return env;
    char buf[4096];
    const ssize_t n=readlink("/proc/self/exe",buf,sizeof buf-1);
    if(n>0){
        buf[n]=0;
        std::string p(buf);
        const auto pos=p.find_last_of('/');
        if(pos!=std::string::npos)return p.substr(0,pos);
    }
    return ".";
}

/* ---------- synthetic owner observation helper ---------- */
inline pcmf::J observe_params(const std::string&project,const std::string&subject,
                              const std::string&note,
                              const std::string&domain="DAILY_ROUTINE",
                              const std::string&event_class="ROUTINE_STATE"){
    pcmf::J p=pcmf::J::object();
    p["project"]=pcmf::J::string(project);
    p["subject"]=pcmf::J::string(subject);
    p["domain"]=pcmf::J::string(domain);
    p["event_class"]=pcmf::J::string(event_class);
    p["note"]=pcmf::J::string(note);
    return p;
}

/* Structured test runner */
struct TestCase { const char*name;void(*fn)(int,char**); };

inline int run_all(std::vector<TestCase> tests,int argc,char**argv){
    long long passed=0,failed=0;
    for(const auto&t:tests){
        try{
            t.fn(argc,argv);
            std::printf("PASS %s\n",t.name);
            std::fflush(stdout);
            passed++;
        }catch(const TestFail&e){
            std::printf("FAIL %s : %s\n",t.name,e.msg.c_str());
            std::fflush(stdout);
            failed++;
        }catch(const pcmf::Fail&e){
            std::printf("FAIL %s : engine fail %s\n",t.name,e.why.c_str());
            std::fflush(stdout);
            failed++;
        }catch(const std::exception&e){
            std::printf("FAIL %s : exception %s\n",t.name,e.what());
            std::fflush(stdout);
            failed++;
        }
    }
    std::printf("SELFTEST_SUMMARY passed=%lld failed=%lld\n",passed,failed);
    return failed==0?0:1;
}

} // namespace test
#endif
