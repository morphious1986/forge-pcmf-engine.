/*
 * PCMF Living Memory R16/R4 - native terminal setup menu (pcmf-setup).
 *
 * Pure C++20 terminal UI: no Python, no Node.js, no ncurses, no network.
 * Engine operations are linked directly; OS service control uses standard
 * systemctl user commands through /bin/sh when a systemd user session is
 * available. Item 10 (Sol integration) is present but DISABLED until the
 * owner explicitly authorizes it; it never assumes Sol is installed.
 */
#include "pcmf_engine.h"
#include "pcmf_util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "pcmf_sha256.h"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace pcmf;

const char*const BANNER=
"==============================================================\n"
"  PCMF Living Memory - Setup & Administration (R16 policy / R4 acceptance)\n"
"  Canonical Library writer: HOLD_R241_R242 (never bypassed)\n"
"  Memory truth belongs to PCMF. No ChatGPT hook is installed.\n"
"==============================================================";

std::string home_dir(){
    const char*h=getenv("HOME");
    return h?std::string(h):std::string();
}

std::string install_conf_path(){const char*p=getenv("PCMF_INSTANCE_CONFIG");if(p&&*p=='/')return p;return home_dir()+"/.config/pcmf/pcmf.conf";}
bool isolated_instance(){const char*p=getenv("PCMF_INSTANCE_CONFIG");return p&&*p=='/';}

void load_install_conf(std::map<std::string,std::string>&out){
    out.clear();
    const std::string path=install_conf_path();
    if(!file_exists(path))return;
    try{
        for(const auto&line:split_lines(read_file_bounded(path,65536))){
            const std::string l=trim(line);
            if(l.empty()||l[0]=='#')continue;
            const auto eq=l.find('=');
            if(eq==std::string::npos)continue;
            out[trim(l.substr(0,eq))]=trim(l.substr(eq+1));
        }
    }catch(const Fail&){}
}
void save_install_conf(const std::map<std::string,std::string>&conf){
    std::string out="# PCMF Living Memory install configuration (R16-R4)\n";
    for(const auto&kv:conf)out+=kv.first+"="+kv.second+"\n";
    const std::string config_path=install_conf_path();
    if(!isolated_instance())ensure_dir(home_dir()+"/.config",0700);
    ensure_dir(config_path.substr(0,config_path.find_last_of('/')),0700);
    write_file_private(config_path,out);
}

void pause_line(){
    std::cout<<"\n[Enter] to continue...";
    std::string dummy;
    std::getline(std::cin,dummy);
}

std::string prompt(const std::string&q,const std::string&dflt=""){
    std::cout<<q;
    if(!dflt.empty())std::cout<<" ["<<dflt<<"]";
    std::cout<<": ";
    std::string line;
    if(!std::getline(std::cin,line))return std::string("__EOF__");
    line=trim(line);
    return line.empty()?dflt:line;
}

std::string resolve_root(const std::map<std::string,std::string>&conf){
    auto it=conf.find("data_root");
    if(it!=conf.end()&&!it->second.empty())return it->second;
    std::string r;
    if(!isolated_instance()&&resolve_default_root(r))return r;
    return isolated_instance()?std::string():home_dir()+"/.local/share/pcmf";
}

bool engine_ready(const std::string&root){
    try{Engine eng(root);return true;}catch(const Fail&){return false;}
}

/* Runs an external command (standard Linux facilities only). */
void run_shell(const std::string&cmd){
    std::cout<<"---\n";
    const int rc=std::system(cmd.c_str());
    std::cout<<"---\n[exit code "<<rc<<"]\n";
}

std::string sibling_binary(const std::string&name){
    char path[4096]={};
    const ssize_t n=readlink("/proc/self/exe",path,sizeof(path)-1);
    if(n<=0||(size_t)n>=sizeof(path)-1)return std::string();
    std::string full(path,(size_t)n);
    const auto slash=full.rfind('/');
    if(slash==std::string::npos)return std::string();
    return full.substr(0,slash+1)+name;
}
std::string package_script(const std::string&name){
    const std::string self=sibling_binary("pcmf-setup");
    const std::string needle="/bin/pcmf-setup";
    if(self.size()<=needle.size()||
       self.compare(self.size()-needle.size(),needle.size(),needle)!=0)
        return std::string();
    return self.substr(0,self.size()-needle.size())+"/scripts/"+name;
}
int run_forge_gpt_r2_setup(const std::string&root,const std::string&socket,
                           const std::string&profile,const std::string&project){
    const std::string script=package_script("configure_forge_gpt_r2.sh");
    if(script.empty()||access(script.c_str(),R_OK)!=0)return 127;
    pid_t pid=fork();
    if(pid<0)return 126;
    if(pid==0){
        if(socket.empty()){
            execl("/bin/sh","sh",script.c_str(),
                  "--root",root.c_str(),
                  "--profile",profile.c_str(),
                  "--project",project.c_str(),
                  (char*)nullptr);
        }else{
            execl("/bin/sh","sh",script.c_str(),
                  "--root",root.c_str(),
                  "--socket",socket.c_str(),
                  "--profile",profile.c_str(),
                  "--project",project.c_str(),
                  (char*)nullptr);
        }
        _exit(127);
    }
    int st=0;
    while(waitpid(pid,&st,0)<0){
        if(errno==EINTR)continue;
        return 126;
    }
    return WIFEXITED(st)?WEXITSTATUS(st):125;
}

int run_local_model_health(const std::string&endpoint,const std::string&model){
    const std::string bin=sibling_binary("pcmf-local-model");
    if(bin.empty()||access(bin.c_str(),X_OK)!=0)return 127;
    pid_t pid=fork();
    if(pid<0)return 126;
    if(pid==0){
        execl(bin.c_str(),bin.c_str(),"health","--endpoint",endpoint.c_str(),
              "--model",model.c_str(),(char*)nullptr);
        _exit(127);
    }
    int st=0;
    while(waitpid(pid,&st,0)<0){
        if(errno==EINTR)continue;
        return 126;
    }
    return WIFEXITED(st)?WEXITSTATUS(st):125;
}

/* Models are optional inference providers, never PCMF memory authorities.
 * This menu persists only non-secret connection metadata. */
/* Independent provider profiles. Neither enables memory transmission or
 * grants model processes authority to write to PCMF. */
void mi_forge_gpt(std::map<std::string,std::string>&conf,const std::string&root){
    std::cout<<"\n[17] Forge GPT R16/R4 local MCP setup\n";
    std::cout<<"Configures the local deterministic R2/R4 PCMF endpoint only.\n";
    std::cout<<"External tunnel credentials remain outside the PCMF package.\n";
    if(!engine_ready(root)){
        std::cout<<"BLOCKED_FORGE_GPT_ROOT_NOT_INITIALIZED\n";
        return;
    }
    const std::string profile=prompt("PCMF profile",
        conf.count("forge_gpt_profile")?conf.at("forge_gpt_profile"):"personal");
    const std::string project=prompt("PCMF project",
        conf.count("forge_gpt_project")?conf.at("forge_gpt_project"):"general");
    if(profile=="__EOF__"||project=="__EOF__"||
       profile.find_first_of("\r\n=")!=std::string::npos||
       project.find_first_of("\r\n=")!=std::string::npos)return;
    const std::string socket=conf.count("socket")?conf.at("socket"):"";
    const int rc=run_forge_gpt_r2_setup(root,socket,profile,project);
    conf["forge_gpt_provider"]="pcmf_r2_mcp";
    conf["forge_gpt_profile"]=profile;
    conf["forge_gpt_project"]=project;
    conf["forge_gpt_memory_transfer"]="false";
    conf["forge_gpt_external_tunnel_configured"]="false";
    conf["forge_gpt_local_adapter_ready"]=rc==0?"true":"false";
    conf["forge_gpt_enabled"]="false";
    save_install_conf(conf);
    if(rc==0)
        std::cout<<"PASS_FORGE_GPT_R16_R4_LOCAL_CONFIG external_tunnel=false\n";
    else
        std::cout<<"BLOCKED_FORGE_GPT_R16_R4_LOCAL_CONFIG exit="<<rc<<"\n";
}
void mi_local_llama(std::map<std::string,std::string>&conf){
    std::cout<<"\n[18] Local llama.cpp direct connection\n";
    std::cout<<"Loopback-only OpenAI-compatible endpoint. The model never becomes PCMF memory authority.\n";
    const std::string endpoint=prompt("Local llama.cpp endpoint",
        conf.count("local_llama_endpoint")?conf.at("local_llama_endpoint"):
        "http://127.0.0.1:8080/v1");
    const std::string name=prompt("Local model id",
        conf.count("local_llama_model")?conf.at("local_llama_model"):"sol");
    if(endpoint=="__EOF__"||name=="__EOF__"||
       endpoint.find_first_of("\r\n=")!=std::string::npos||
       name.find_first_of("\r\n=")!=std::string::npos||name.empty())return;

    conf["local_llama_provider"]="llama_cpp";
    conf["local_llama_endpoint"]=endpoint;
    conf["local_llama_model"]=name;
    conf["local_llama_memory_transfer"]="false";
    conf["local_llama_enabled"]="false";
    save_install_conf(conf);

    std::cout<<"Testing /v1/models through packaged loopback connector...\n";
    const int rc=run_local_model_health(endpoint,name);
    if(rc==0){
        conf["local_llama_enabled"]="true";
        save_install_conf(conf);
        std::cout<<"PASS_LOCAL_LLAMA_CONNECTION model="<<name
                 <<" memory_transfer=false\n";
    }else{
        std::cout<<"BLOCKED_LOCAL_LLAMA_CONNECTION_NOT_VERIFIED exit="<<rc
                 <<" (configuration saved but disabled)\n";
    }
}

/* ---------------- menu item implementations ---------------- */

void mi_init(std::map<std::string,std::string>&conf){
    std::cout<<"\n[1] First-time installation and initialization\n";
    const std::string root=prompt("Memory storage root",resolve_root(conf));
    if(root=="__EOF__")return;
    if(Engine::looks_initialized(root)){
        std::cout<<"This root is ALREADY initialized. Leaving it unchanged.\n";
        conf["data_root"]=root;save_install_conf(conf);
        return;
    }
    const std::string profile=prompt("Default profile id","personal");
    const std::string project=prompt("Default project id","general");
    try{
        Engine::init_root(root,profile,project);
        conf["data_root"]=root;save_install_conf(conf);
        Engine eng(root);
        std::cout<<"Initialized.\n"<<eng.call("owner","health.get",J::object())<<"\n";
        std::cout<<"Owner key: "<<root<<"/keys/owner.key (0600). Keep it private.\n";
    }catch(const Fail&e){
        std::cout<<"INITIALIZATION FAILED: "<<e.why<<"\n";
    }
}

void mi_storage(std::map<std::string,std::string>&conf){
    std::cout<<"\n[2] Selecting the memory storage location\n";
    std::cout<<"Current: "<<resolve_root(conf)<<"\n";
    const std::string root=prompt("New absolute storage root (no '..' components)");
    if(root=="__EOF__"||root.empty())return;
    if(root.empty()||root[0]!='/'||contains_component_dotdot(root)){
        std::cout<<"Rejected: path must be absolute without '..' components.\n";
        return;
    }
    conf["data_root"]=root;save_install_conf(conf);
    if(!Engine::looks_initialized(root))
        std::cout<<"Saved. The root is not initialized yet; use menu item [1].\n";
    else
        std::cout<<"Saved and existing root accepted.\n";
}

void mi_owner(const std::map<std::string,std::string>&conf){
    std::cout<<"\n[3] Local owner authentication\n";
    const std::string root=resolve_root(conf);
    if(!engine_ready(root)){std::cout<<"Engine not initialized at "<<root<<"\n";return;}
    const std::string keyfile=root+"/keys/owner.key";
    if(!file_exists(keyfile)){std::cout<<"Owner key missing.\n";return;}
    try{
        const std::string key=read_file_bounded(keyfile,64);
        std::cout<<"Owner key present: "<<keyfile<<"\n";
        std::cout<<"Fingerprint: "<<sha256_hex(key).substr(0,16)<<"\n";
        std::cout<<"(Raw key material is never displayed.)\n";
        const std::string rot=prompt("Rotate owner key? type ROTATE or press Enter","");
        if(rot=="ROTATE"){
            write_file_private(keyfile,[](){
                std::string k=random_hex(32);
                std::string raw;raw.resize(32);
                uint8_t buf[32];
                if(!pcmf_from_hex(k.c_str(),buf,32))die("KEY_DERIV_FAILED");
                memcpy(raw.data(),buf,32);
                return raw;
            }());
            std::cout<<"Owner key rotated. Previously issued frames are invalid.\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_profiles(const std::string&root){
    std::cout<<"\n[4] Memory profiles and project scopes\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<eng.call("owner","config.get",J::object())<<"\n";
        const std::string add=prompt("Add profile? type ADD or press Enter","");
        if(add=="ADD"){
            J p=J::object();
            p["profile_id"]=J::string(prompt("New profile id"));
            J projects=J::array();
            std::string list=prompt("Comma-separated projects");
            size_t start=0;
            while(start<list.size()){
                const size_t comma=list.find(',',start);
                std::string item=trim(list.substr(start,
                    comma==std::string::npos?std::string::npos:comma-start));
                if(!item.empty())projects.a.push_back(J::string(item));
                if(comma==std::string::npos)break;
                start=comma+1;
            }
            p["projects"]=projects;
            std::cout<<eng.call("owner","profiles.add",p)<<"\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_clients(const std::string&root){
    std::cout<<"\n[5] Register or revoke local AI clients\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<eng.call("owner","client.list",J::object())<<"\n";
        const std::string action=prompt("Action: register / revoke / (blank to skip)","") ;
        if(action=="register"){
            J p=J::object();
            p["client_id"]=J::string(prompt("Client id (e.g. forge_local)"));
            p["role"]=J::string(prompt("Role: forge / sol / test","forge"));
            J sc=J::object();
            sc["profiles"]=J::array();
            sc["projects"]=J::array();
            sc["subjects"]=J::array();
            sc["event_classes"]=J::array();
            {
                auto fill=[&](const char*field,const std::string&dflt){
                    const std::string v=prompt(std::string("Allowed ")+std::string(field)+
                        " (comma separated, * allowed)",dflt);
                    size_t start=0;
                    while(start<v.size()){
                        const size_t comma=v.find(',',start);
                        std::string item=trim(v.substr(start,
                            comma==std::string::npos?std::string::npos:comma-start));
                        if(!item.empty())sc[field].a.push_back(J::string(item));
                        if(comma==std::string::npos)break;
                        start=comma+1;
                    }
                };
                fill("profiles","personal");
                fill("projects","general");
                fill("subjects","*");
                fill("event_classes","PREFERENCE,PROJECT_STATE,WORKFLOW_STATE,"
                    "FAILURE_GOTCHA,OBSERVATION,ROUTINE_STATE,COMMITMENT,"
                    "CORRECTION,REVOCATION");
            }
            sc["max_privacy"]=J::string("INTERNAL_PROJECT");
            p["scopes"]=sc;
            std::cout<<eng.call("owner","client.register",p)<<"\n";
            std::cout<<"Key file written with 0600 permissions; deliver it to the\n"
              "client out-of-band. Registration never impersonates ChatGPT.\n";
        }else if(action=="revoke"){
            J p=J::object();
            p["client_id"]=J::string(prompt("Client id to revoke"));
            std::cout<<eng.call("owner","client.revoke",p)<<"\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_privacy(const std::string&root){
    std::cout<<"\n[6] Privacy and sensitive-memory controls\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<eng.call("owner","review.list",J::object())<<"\n";
        std::cout<<"Sensitive candidates are held as HASH-ONLY stubs; raw content\n"
          "is never persisted before review.\n";
        const std::string act=prompt("Resolve a token? allow_rule / allow_once / reject / (blank)","");
        if(act=="allow_rule"||act=="reject"||act=="allow_once"){
            J p=J::object();
            p["token"]=J::string(prompt("Review token"));
            p["decision"]=J::string(act);
            if(act=="allow_once"){
                const std::string note=prompt("Exact reviewed content to admit");
                if(!note.empty())p["note"]=J::string(note);
            }
            std::cout<<eng.call("owner","review.resolve",p)<<"\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_behavior(const std::string&root){
    std::cout<<"\n[7] Memory admission and retrieval behavior\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<eng.call("owner","config.get",J::object())<<"\n";
        const char*const keys[]={"hot_days","warm_days","cold_days",
            "ts_window_past","ts_window_future","retrieval_default_limit",
            "auto_admit"};
        for(const char*k:keys){
            const std::string v=prompt(std::string("Set ")+k+" (blank to skip)","");
            if(v.empty())continue;
            J p=J::object();
            p["key"]=J::string(k);
            p["value"]=J::string(v);
            std::cout<<eng.call("owner","config.set",p)<<"\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_health(const std::string&root){
    std::cout<<"\n[8] HOT subjects and memory health\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<eng.status_json()<<"\n";
        std::cout<<eng.call("owner","hot.get",J::object())<<"\n";
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_forge(const std::string&root){
    std::cout<<"\n[9] Forge integration\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<"Transport: AF_UNIX socket (local only; no network, no\n"
          "message interception). Protocol: PCMF_IPv1 - see docs/FORGE_INTEGRATION.md\n";
        std::cout<<eng.call("owner","client.list",J::object())<<"\n";
        const std::string act=prompt("Register a forge client now? type REGISTER or (blank)","");
        if(act=="REGISTER"){
            J p=J::object();
            p["client_id"]=J::string(prompt("Client id","forge_local"));
            p["role"]=J::string("forge");
            J sc=J::object();
            sc["profiles"]=J::array();sc["profiles"].a.push_back(J::string("personal"));
            sc["projects"]=J::array();sc["projects"].a.push_back(J::string("general"));
            sc["subjects"]=J::array();sc["subjects"].a.push_back(J::string("*"));
            sc["event_classes"]=J::array();
            for(const char*c:{"PREFERENCE","PROJECT_STATE","WORKFLOW_STATE",
                "FAILURE_GOTCHA","OBSERVATION","ROUTINE_STATE","COMMITMENT",
                "CORRECTION","REVOCATION"})
                sc["event_classes"].a.push_back(J::string(c));
            sc["max_privacy"]=J::string("INTERNAL_PROJECT");
            p["scopes"]=sc;
            std::cout<<eng.call("owner","client.register",p)<<"\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_sol(const std::string&root){
    std::cout<<"\n[10] Future Sol integration (DISABLED by default)\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<eng.call("owner","config.get",J::object())<<"\n";
        std::cout<<"Sol production integration is NOT authorized and Sol is not\n"
          "assumed to be installed. Enabling here only prepares the local\n"
          "adapter configuration described in docs/SOL_INTEGRATION.md.\n";
        const std::string act=prompt("Type ENABLE-SOL to authorize, DISABLE-SOL to revoke, blank to skip","");
        if(act=="ENABLE-SOL"){
            const std::string ack=prompt("Type exactly: I AUTHORIZE SOL INTEGRATION","");
            if(ack!="I AUTHORIZE SOL INTEGRATION"){
                std::cout<<"Authorization text mismatch - nothing changed.\n";
                return;
            }
            std::cout<<eng.call("owner","sol.enable",J::object())<<"\n";
        }else if(act=="DISABLE-SOL"){
            std::cout<<eng.call("owner","sol.disable",J::object())<<"\n";
        }
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_diagnostics(const std::string&root){
    std::cout<<"\n[11] Diagnostics and tests\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        std::cout<<"-- store.verify --\n"<<eng.call("owner","store.verify",J::object())<<"\n";
        std::cout<<"-- store.replay --\n"<<eng.call("owner","store.replay",J::object())<<"\n";
        const std::string st=prompt("Run full native selftest? (selftest path or blank)","") ;
        if(!st.empty()&&file_exists(st))run_shell(st+" quick");
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_backup(const std::string&root){
    std::cout<<"\n[12] Create and verify backups\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        const std::string name=prompt("Backup name","backup-"+std::to_string(now_epoch()));
        J p=J::object();p["name"]=J::string(name);
        std::cout<<eng.call("owner","backup.create",p)<<"\n";
        std::cout<<eng.call("owner","backup.verify",p)<<"\n";
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_restore(const std::string&root){
    std::cout<<"\n[13] Restore a verified backup\n";
    if(!engine_ready(root)){std::cout<<"Engine not initialized.\n";return;}
    try{
        Engine eng(root);
        const std::string name=prompt("Backup name to restore");
        if(name.empty())return;
        const std::string ack=prompt("Type RESTORE "+name+" to confirm",
                                     "");
        if(ack!="RESTORE "+name){
            std::cout<<"Confirmation mismatch - nothing changed.\n";
            return;
        }
        J p=J::object();p["name"]=J::string(name);
        std::cout<<eng.call("owner","backup.restore",p)<<"\n";
    }catch(const Fail&e){std::cout<<"ERROR: "<<e.why<<"\n";}
}

void mi_update(){
    if(isolated_instance()){std::cout<<"Global update disabled for isolated instance.\n";return;}
    std::cout<<"\n[14] Update the application\n";
    const std::string home=home_dir();
    const std::string script=home+"/.local/lib/pcmf/current/scripts/install.sh";
    if(!file_exists(script)){
        std::cout<<"Installer not found at "<<script<<"\n"
          "Run the offline installer from the release package instead.\n";
        return;
    }
    std::cout<<"This runs the package installer in UPDATE mode. Existing memory\n"
      "data is protected; service cutover requires explicit authorization.\n";
    run_shell("sh \""+script+"\"");
}

void mi_service(){
    if(isolated_instance()){std::cout<<"Global service management disabled for isolated instance.\n";return;}
    std::cout<<"\n[15] PCMF service (start / stop / check)\n";
    const bool have_systemd=(std::system("command -v systemctl >/dev/null 2>&1")==0);
    if(!have_systemd){
        std::cout<<"SYSTEMD_USER_SESSION_UNAVAILABLE: service activation is\n"
          "ON HOLD. You can run the daemon directly:\n"
          "  ~/.local/lib/pcmf/current/bin/pcmf-serve --root <data root>\n";
        return;
    }
    const std::string act=prompt("Action: start / stop / restart / status","status");
    if(act=="start"||act=="stop"||act=="restart"||act=="status")
        run_shell("systemctl --user "+act+" pcmf.service; systemctl --user status pcmf.service --no-pager | head -12");
    else
        std::cout<<"Unknown action.\n";
}

void mi_uninstall(){
    if(isolated_instance()){std::cout<<"Global uninstall disabled for isolated instance.\n";return;}
    std::cout<<"\n[16] Uninstall or roll back a release\n";
    const std::string home=home_dir();
    const std::string rb=home+"/.local/lib/pcmf/current/scripts/install.sh";
    const std::string un=home+"/.local/lib/pcmf/current/scripts/uninstall.sh";
    const std::string act=prompt("rollback / uninstall / (blank to skip)","");
    if(act=="rollback"&&file_exists(rb))run_shell("sh \""+rb+"\" --rollback");
    else if(act=="uninstall"&&file_exists(un))run_shell("sh \""+un+"\"");
    else std::cout<<"Nothing done (scripts not found or unknown action).\n"
      "Memory data and backups are PRESERVED by uninstall defaults.\n";
}

} // namespace

int main(int argc,char**argv){
    if(argc==2&&std::string(argv[1])=="--selfcheck"){
        std::printf("SETUP_SELFCHECK_OK engine=%s canonical_writer=%s\n",
                    PCMF_VERSION_STRING,PCMF_CANONICAL_HOLD);
        return 0;
    }
    std::map<std::string,std::string> conf;
    load_install_conf(conf);
    for(;;){
        std::cout<<"\n"<<BANNER<<"\n";
        std::cout<<"Data root: "<<resolve_root(conf)<<"\n";
        std::cout<<"\n"
          " 1)  First-time installation and initialization\n"
          " 2)  Select the memory storage location\n"
          " 3)  Local owner authentication (view / rotate)\n"
          " 4)  Memory profiles and project scopes\n"
          " 5)  Register or revoke local AI clients\n"
          " 6)  Privacy and sensitive-memory controls\n"
          " 7)  Memory admission and retrieval behavior\n"
          " 8)  View HOT subjects and memory health\n"
          " 9)  Forge integration\n"
          "10)  Future Sol integration (disabled by default)\n"
          "11)  Run diagnostics and tests\n"
          "12)  Create and verify backups\n"
          "13)  Restore a verified backup\n"
          "14)  Update the application\n"
          "15)  Service: start / stop / check\n"
          "16)  Uninstall or roll back a release\n"
          "17)  Configure Forge GPT connection\n"
          "18)  Configure local llama.cpp connection\n"
          " q)  Quit\n";
        std::cout<<"Select: ";
        std::string choice;
        if(!std::getline(std::cin,choice))break;
        choice=trim(choice);
        if(choice=="q"||choice=="Q"||choice=="quit")break;
        const std::string root=resolve_root(conf);
        if(choice=="1")mi_init(conf);
        else if(choice=="2")mi_storage(conf);
        else if(choice=="3")mi_owner(conf);
        else if(choice=="4")mi_profiles(root);
        else if(choice=="5")mi_clients(root);
        else if(choice=="6")mi_privacy(root);
        else if(choice=="7")mi_behavior(root);
        else if(choice=="8")mi_health(root);
        else if(choice=="9")mi_forge(root);
        else if(choice=="10")mi_sol(root);
        else if(choice=="11")mi_diagnostics(root);
        else if(choice=="12")mi_backup(root);
        else if(choice=="13")mi_restore(root);
        else if(choice=="14")mi_update();
        else if(choice=="15")mi_service();
        else if(choice=="16")mi_uninstall();
        else if(choice=="17")mi_forge_gpt(conf,root);
        else if(choice=="18")mi_local_llama(conf);
        else std::cout<<"Unknown selection.\n";
        if(std::cin.eof())break;
        pause_line();
    }
    std::cout<<"Goodbye. canonical_writer=HOLD_R241_R242\n";
    return 0;
}
