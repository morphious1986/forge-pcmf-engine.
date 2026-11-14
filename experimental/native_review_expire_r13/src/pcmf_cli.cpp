/*
 * PCMF Living Memory R14 - native client CLI (pcmf).
 *
 * Every memory operation - including local owner commands - is dispatched
 * through Engine::request() with a signed PCMF_IPv1 frame, so direct local
 * use and daemon use share one authorization and replay path. This CLI is
 * the reference local client for Forge integration and the future Sol
 * adapter; it never identifies itself as ChatGPT and never touches any
 * canonical Library store (HOLD_R241_R242 echoed in every response).
 */
#include "pcmf_engine.h"
#include "pcmf_util.h"

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

using namespace pcmf;

int emit(const std::string&line){
    std::cout<<line<<"\n";
    if(line.find("\"status\":\"OK\"")!=std::string::npos||
       line.find("\"status\":\"REVIEW_REQUIRED\"")!=std::string::npos||
       line.find("\"status\":\"DUPLICATE_NOOP\"")!=std::string::npos)return 0;
    if(line.find("\"status\":\"REJECT\"")!=std::string::npos)return 5;
    if(line.find("\"status\":\"DENIED\"")!=std::string::npos)return 6;
    return 2;
}

std::string opt_root(int argc,char**argv,bool required=true){
    std::string root;
    for(int i=1;i<argc;i++){
        const std::string a=argv[i];
        if(a=="--root"&&i+1<argc)root=argv[++i];
    }
    if(root.empty())resolve_default_root(root);
    if(root.empty()&&required){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
          "\"reason\":\"NO_DATA_ROOT_CONFIGURED\",\"canonical_writer\":\""
          <<PCMF_CANONICAL_HOLD<<"\",\"engine\":\""<<PCMF_VERSION_STRING<<"\"}\n";
        std::exit(2);
    }
    return root;
}

bool has_flag(int argc,char**argv,const std::string&flag){
    for(int i=1;i<argc;i++)if(flag==argv[i])return true;
    return false;
}
std::string opt_value(int argc,char**argv,const std::string&flag){
    for(int i=1;i<argc;i++)
        if(flag==argv[i]&&i+1<argc)return argv[i+1];
    return std::string();
}

std::string read_note(int argc,char**argv){
    std::string note=opt_value(argc,argv,"--note");
    if(note.empty()){
        const std::string file=opt_value(argc,argv,"--note-file");
        if(!file.empty()){
            try{note=read_file_bounded(file,2800);}
            catch(const Fail&){return std::string();}
        }
    }
    /* strip a single trailing newline for shell convenience */
    while(!note.empty()&&(note.back()=='\n'||note.back()=='\r'))note.pop_back();
    return note;
}

int cmd_init(int argc,char**argv){
    const std::string root=opt_value(argc,argv,"--root");
    if(root.empty()){
        std::cout<<"{\"status\":\"REJECT\",\"reason\":\"ROOT_REQUIRED\","
          "\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
    try{
        std::string profile=opt_value(argc,argv,"--profile");
        std::string project=opt_value(argc,argv,"--project");
        if(profile.empty())profile="personal";
        if(project.empty())project="general";
        Engine::init_root(root,profile,project);
        Engine eng(root);
        std::cout<<eng.call("owner","health.get",J::object())<<"\n";
        return 0;
    }catch(const Fail&e){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\",\"reason\":\""
          <<e.why<<"\",\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
}

int cmd_call(int argc,char**argv,const std::string&op,J params){
    const std::string root=opt_root(argc,argv);
    std::string client=opt_value(argc,argv,"--client");
    if(client.empty())client="owner";
    try{
        Engine eng(root);
        std::string nonce=opt_value(argc,argv,"--nonce");
        std::cout<<eng.call(client,op,params,nonce)<<"\n";
        return 0;
    }catch(const Fail&e){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\",\"reason\":\""
          <<e.why<<"\",\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
}

void usage(){
    std::cout<<"PCMF Living Memory "<<PCMF_VERSION_STRING<<"\n"
      "usage:\n"
      "  pcmf init --root PATH [--profile N --project N]\n"
      "  pcmf status|verify|replay|recover|state|health [--root PATH] [--client ID]\n"
      "  pcmf hot [--profile P --project J --subject S] [--limit N] [--include-warm]\n"
      "  pcmf observe --project J --subject S --domain D --class C --note TEXT\n"
      "             [--profile P] [--privacy PC] [--ref EVENTID] [--client ID]\n"
      "             [--note-file F] [--nonce HEX32]\n"
      "  pcmf proof --event-id ID\n"
      "  pcmf clients register --id ID --role forge|sol|test --scopes-file F\n"
      "  pcmf clients revoke --id ID | pcmf clients list\n"
      "  pcmf review list | pcmf review resolve --token T --decision authorize_once|allow_once|allow_rule|reject [--note-file F]\n  pcmf review expire-once --token T --note-hash H (owner-only, after TTL)\n"
      "  pcmf review submit --token T --note TEXT --client ID\n"
      "  pcmf backup create [--name N] | verify --name N | restore --name N\n"
      "  pcmf config get | pcmf config set --key K --value V\n"
      "  pcmf sol enable | pcmf sol disable\n"
      "  pcmf profiles add --profile P --projects A,B\n"
      "  pcmf send --socket PATH --frame-file F   (raw PCMF_IPv1 frame over daemon socket)\n"
      "  pcmf version\n";
}

int cmd_send(int argc,char**argv){
    const std::string socket_path=opt_value(argc,argv,"--socket");
    const std::string file=opt_value(argc,argv,"--frame-file");
    if(socket_path.empty()||file.empty()){usage();return 2;}
    std::string frame;
    try{frame=read_file_bounded(file,8328);}
    catch(const Fail&){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
          "\"reason\":\"FRAME_FILE_UNREADABLE\",\"canonical_writer\":\""
          <<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
          "\"reason\":\"SOCKET_OPEN_FAILED\",\"canonical_writer\":\""
          <<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
    sockaddr_un addr{};
    addr.sun_family=AF_UNIX;
    if(socket_path.size()>=sizeof addr.sun_path){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
          "\"reason\":\"SOCKET_PATH_TOO_LONG\",\"canonical_writer\":\""
          <<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
    std::memcpy(addr.sun_path,socket_path.c_str(),socket_path.size());
    if(connect(fd,(const sockaddr*)&addr,sizeof addr)!=0){
        std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\","
          "\"reason\":\"DAEMON_NOT_REACHABLE\",\"canonical_writer\":\""
          <<PCMF_CANONICAL_HOLD<<"\"}\n";
        return 2;
    }
    size_t off=0;
    while(off<frame.size()){
        const ssize_t n=write(fd,frame.data()+off,frame.size()-off);
        if(n<0){if(errno==EINTR)continue;close(fd);return 2;}
        off+=(size_t)n;
    }
    std::string resp;
    char buf[4096];
    for(;;){
        const ssize_t n=read(fd,buf,sizeof buf);
        if(n<=0)break;
        resp.append(buf,(size_t)n);
        if(resp.size()>65536)break;
        if(!resp.empty()&&resp.back()=='\n')break;
    }
    close(fd);
    std::cout<<resp;
    return emit(resp.empty()?"{}":resp);
}

} // namespace

int main(int argc,char**argv){
    if(argc<2){usage();return 2;}
    const std::string cmd=argv[1];
    if(cmd=="version"||cmd=="--version"){
        std::cout<<"{\"version\":\""<<PCMF_VERSION_STRING<<"\",\"protocol\":\""
          <<PCMF_PROTOCOL<<"\",\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD
          <<"\",\"c_standard\":\"C11\",\"cpp_standard\":\"C++20\"}\n";
        return 0;
    }
    if(cmd=="help"||cmd=="--help"){usage();return 0;}
    if(cmd=="init")return cmd_init(argc,argv);
    if(cmd=="send")return cmd_send(argc,argv);
    if(cmd=="status"){
        const std::string root=opt_root(argc,argv);
        try{Engine eng(root);std::cout<<eng.status_json()<<"\n";return 0;}
        catch(const Fail&e){
            std::cout<<"{\"status\":\"HOLD_INTEGRITY_OR_AUTHORITY\",\"reason\":\""
              <<e.why<<"\",\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
            return 2;
        }
    }
    if(cmd=="verify")return cmd_call(argc,argv,"store.verify",J::object());
    if(cmd=="replay")return cmd_call(argc,argv,"store.replay",J::object());
    if(cmd=="recover")return cmd_call(argc,argv,"store.recover",J::object());
    if(cmd=="state")return cmd_call(argc,argv,"memory.state",J::object());
    if(cmd=="health")return cmd_call(argc,argv,"health.get",J::object());
    if(cmd=="hot"){
        J p=J::object();
        const std::string prof=opt_value(argc,argv,"--profile");
        const std::string proj=opt_value(argc,argv,"--project");
        const std::string subj=opt_value(argc,argv,"--subject");
        if(!prof.empty())p["profile"]=J::string(prof);
        if(!proj.empty())p["project"]=J::string(proj);
        if(!subj.empty())p["subject"]=J::string(subj);
        const std::string lim=opt_value(argc,argv,"--limit");
        if(!lim.empty()){
            long long v=0;
            if(!valid_epoch_string(lim,v)||v<1||v>50){
                std::cout<<"{\"status\":\"REJECT\",\"reason\":\"LIMIT_INVALID\","
                  "\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
                return 2;
            }
            p["limit"]=J::number(v);
        }
        if(has_flag(argc,argv,"--include-warm"))p["include_warm"]=J::boolean(true);
        return cmd_call(argc,argv,"hot.get",p);
    }
    if(cmd=="observe"){
        J p=J::object();
        const std::string prof=opt_value(argc,argv,"--profile");
        const std::string proj=opt_value(argc,argv,"--project");
        const std::string subj=opt_value(argc,argv,"--subject");
        const std::string dom=opt_value(argc,argv,"--domain");
        const std::string cls=opt_value(argc,argv,"--class");
        const std::string privacy=opt_value(argc,argv,"--privacy");
        const std::string ref=opt_value(argc,argv,"--ref");
        const std::string note=read_note(argc,argv);
        if(!prof.empty())p["profile"]=J::string(prof);
        if(proj.empty()||subj.empty()||dom.empty()||cls.empty()||note.empty()){
            std::cout<<"{\"status\":\"REJECT\",\"reason\":\"OBSERVE_ARGS_REQUIRED\","
              "\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
            return 2;
        }
        p["project"]=J::string(proj);
        p["subject"]=J::string(subj);
        p["domain"]=J::string(dom);
        p["event_class"]=J::string(cls);
        p["note"]=J::string(note);
        if(!privacy.empty())p["privacy_class"]=J::string(privacy);
        if(!ref.empty())p["ref_event_id"]=J::string(ref);
        return cmd_call(argc,argv,"observe.submit",p);
    }
    if(cmd=="proof"){
        J p=J::object();
        p["event_id"]=J::string(opt_value(argc,argv,"--event-id"));
        return cmd_call(argc,argv,"proof.get",p);
    }
    if(cmd=="clients"){
        const std::string sub=argc>2?argv[2]:"list";
        if(sub=="list")return cmd_call(argc,argv,"client.list",J::object());
        if(sub=="register"){
            J p=J::object();
            p["client_id"]=J::string(opt_value(argc,argv,"--id"));
            p["role"]=J::string(opt_value(argc,argv,"--role"));
            const std::string sf=opt_value(argc,argv,"--scopes-file");
            if(sf.empty()){
                std::cout<<"{\"status\":\"REJECT\",\"reason\":\"SCOPES_FILE_REQUIRED\","
                  "\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
                return 2;
            }
            try{p["scopes"]=parse(read_file_bounded(sf,65536));}
            catch(const Fail&){
                std::cout<<"{\"status\":\"REJECT\",\"reason\":\"SCOPES_UNREADABLE\","
                  "\"canonical_writer\":\""<<PCMF_CANONICAL_HOLD<<"\"}\n";
                return 2;
            }
            return cmd_call(argc,argv,"client.register",p);
        }
        if(sub=="revoke"){
            J p=J::object();
            p["client_id"]=J::string(opt_value(argc,argv,"--id"));
            return cmd_call(argc,argv,"client.revoke",p);
        }
        usage();return 2;
    }
    if(cmd=="review"){
        const std::string sub=argc>2?argv[2]:"list";
        if(sub=="list")return cmd_call(argc,argv,"review.list",J::object());
        if(sub=="resolve"){
            J p=J::object();
            p["token"]=J::string(opt_value(argc,argv,"--token"));
            p["decision"]=J::string(opt_value(argc,argv,"--decision"));
            const std::string note=read_note(argc,argv);
            if(!note.empty())p["note"]=J::string(note);
            return cmd_call(argc,argv,"review.resolve",p);
        }
        if(sub=="expire-once"){
            J p=J::object();
            p["token"]=J::string(opt_value(argc,argv,"--token"));
            p["note_hash"]=J::string(opt_value(argc,argv,"--note-hash"));
            return cmd_call(argc,argv,"review.expire_once",p);
        }
        if(sub=="submit"){
            J p=J::object();
            p["token"]=J::string(opt_value(argc,argv,"--token"));
            const std::string note=read_note(argc,argv);
            if(!note.empty())p["note"]=J::string(note);
            return cmd_call(argc,argv,"review.submit",p);
        }
        usage();return 2;
    }
    if(cmd=="backup"){
        const std::string sub=argc>2?argv[2]:"create";
        J p=J::object();
        const std::string name=opt_value(argc,argv,"--name");
        if(!name.empty())p["name"]=J::string(name);
        if(sub=="create")return cmd_call(argc,argv,"backup.create",p);
        if(sub=="verify")return cmd_call(argc,argv,"backup.verify",p);
        if(sub=="restore")return cmd_call(argc,argv,"backup.restore",p);
        usage();return 2;
    }
    if(cmd=="config"){
        const std::string sub=argc>2?argv[2]:"get";
        if(sub=="get")return cmd_call(argc,argv,"config.get",J::object());
        if(sub=="set"){
            J p=J::object();
            p["key"]=J::string(opt_value(argc,argv,"--key"));
            p["value"]=J::string(opt_value(argc,argv,"--value"));
            return cmd_call(argc,argv,"config.set",p);
        }
        usage();return 2;
    }
    if(cmd=="sol"){
        const std::string sub=argc>2?argv[2]:"status";
        if(sub=="enable")return cmd_call(argc,argv,"sol.enable",J::object());
        if(sub=="disable")return cmd_call(argc,argv,"sol.disable",J::object());
        return cmd_call(argc,argv,"config.get",J::object());
    }
    if(cmd=="profiles"){
        const std::string sub=argc>2?argv[2]:"list";
        if(sub=="add"){
            J p=J::object();
            p["profile_id"]=J::string(opt_value(argc,argv,"--profile"));
            J projects=J::array();
            const std::string list=opt_value(argc,argv,"--projects");
            size_t start=0;
            while(start<list.size()||list.empty()){
                size_t comma=list.find(',',start);
                std::string item=list.substr(start,
                    comma==std::string::npos?std::string::npos:comma-start);
                if(!item.empty())projects.a.push_back(J::string(trim(item)));
                if(comma==std::string::npos)break;
                start=comma+1;
            }
            p["projects"]=projects;
            return cmd_call(argc,argv,"profiles.add",p);
        }
        return cmd_call(argc,argv,"config.get",J::object());
    }
    usage();
    return 2;
}
