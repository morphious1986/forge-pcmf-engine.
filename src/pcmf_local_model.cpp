// PCMF local llama.cpp connector: loopback-only OpenAI-compatible HTTP transport.
// This is an inference helper only. It never reads or writes PCMF memory and
// never grants a model process PCMF authority.
#include "pcmf_json.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using pcmf::J;
using pcmf::dump;
using pcmf::parse;

namespace {

struct Fail : std::runtime_error {
    explicit Fail(const std::string& s) : std::runtime_error(s) {}
};

[[noreturn]] void fail(const std::string& s) { throw Fail(s); }

struct Endpoint {
    std::string host;
    int port = 8080;
    std::string base = "/v1";
};

bool digits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) if (c < '0' || c > '9') return false;
    return true;
}

Endpoint parse_endpoint(const std::string& raw) {
    const std::string prefix = "http://";
    if (raw.rfind(prefix, 0) != 0) fail("LOOPBACK_HTTP_ENDPOINT_REQUIRED");
    std::string rest = raw.substr(prefix.size());
    if (rest.empty() || rest.find('@') != std::string::npos ||
        rest.find('?') != std::string::npos || rest.find('#') != std::string::npos)
        fail("ENDPOINT_INVALID");

    std::string authority;
    std::string path;
    const auto slash = rest.find('/');
    if (slash == std::string::npos) {
        authority = rest;
        path = "/v1";
    } else {
        authority = rest.substr(0, slash);
        path = rest.substr(slash);
    }

    std::string host = authority;
    int port = 8080;
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        const std::string p = authority.substr(colon + 1);
        if (!digits(p)) fail("ENDPOINT_PORT_INVALID");
        const long v = std::strtol(p.c_str(), nullptr, 10);
        if (v < 1 || v > 65535) fail("ENDPOINT_PORT_INVALID");
        port = static_cast<int>(v);
    }

    if (host != "127.0.0.1" && host != "localhost")
        fail("NON_LOOPBACK_ENDPOINT_REJECTED");
    if (path.empty()) path = "/v1";
    if (path.front() != '/' || path.find("..") != std::string::npos)
        fail("ENDPOINT_PATH_INVALID");
    while (path.size() > 1 && path.back() == '/') path.pop_back();

    Endpoint ep;
    ep.host = "127.0.0.1";
    ep.port = port;
    ep.base = path;
    return ep;
}

std::string http(const Endpoint& ep, const std::string& method,
                 const std::string& route, const std::string& body) {
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) fail("LOCAL_MODEL_SOCKET_FAILED");

    timeval tv{20, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        close(fd);
        fail("LOCAL_MODEL_TIMEOUT_SETUP_FAILED");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(ep.port));
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(fd);
        fail("LOOPBACK_ADDRESS_FAILED");
    }
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        fail("LOCAL_MODEL_UNREACHABLE");
    }

    const std::string target = ep.base + route;
    std::string req = method + " " + target + " HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n";
    if (method == "POST") {
        req += "Content-Type: application/json\r\n";
        req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += "\r\n";
    if (method == "POST") req += body;

    size_t off = 0;
    while (off < req.size()) {
        const ssize_t n = send(fd, req.data() + off, req.size() - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            fail("LOCAL_MODEL_SEND_FAILED");
        }
        off += static_cast<size_t>(n);
    }

    std::string response;
    char buf[8192];
    for (;;) {
        const ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n == 0) break;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            close(fd);
            fail("LOCAL_MODEL_RESPONSE_TIMEOUT");
        }
        response.append(buf, static_cast<size_t>(n));
        if (response.size() > 4u * 1024u * 1024u) {
            close(fd);
            fail("LOCAL_MODEL_RESPONSE_TOO_LARGE");
        }
    }
    close(fd);

    const auto header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) fail("LOCAL_MODEL_HTTP_INVALID");
    const auto line_end = response.find("\r\n");
    if (line_end == std::string::npos) fail("LOCAL_MODEL_HTTP_INVALID");
    const std::string status = response.substr(0, line_end);
    if (status.find(" 200 ") == std::string::npos)
        fail("LOCAL_MODEL_HTTP_NOT_OK");
    return response.substr(header_end + 4);
}

std::vector<std::string> model_ids(const Endpoint& ep) {
    J j = parse(http(ep, "GET", "/models", ""));
    if (j.t != J::Obj || !j.has("data") || j.at("data").t != J::Arr)
        fail("LOCAL_MODEL_MODELS_INVALID");
    std::vector<std::string> out;
    for (const J& item : j.at("data").a) {
        if (item.t == J::Obj && item.has("id") && item.at("id").t == J::Str &&
            !item.at("id").s.empty() && item.at("id").s.size() <= 256) {
            out.push_back(item.at("id").s);
        }
    }
    if (out.empty()) fail("LOCAL_MODEL_NO_MODELS");
    return out;
}

bool has_model(const std::vector<std::string>& ids, const std::string& model) {
    for (const auto& id : ids) if (id == model) return true;
    return false;
}

std::string read_stdin_bounded() {
    std::string in;
    char buf[4096];
    while (std::cin.good()) {
        std::cin.read(buf, sizeof(buf));
        const std::streamsize n = std::cin.gcount();
        if (n > 0) in.append(buf, static_cast<size_t>(n));
        if (in.size() > 32768) fail("PROMPT_TOO_LARGE");
    }
    if (in.empty()) fail("PROMPT_REQUIRED_ON_STDIN");
    return in;
}

std::string arg_value(int argc, char** argv, const std::string& key,
                      const std::string& dflt = "") {
    for (int i = 2; i < argc; ++i) {
        if (argv[i] == key && i + 1 < argc) return argv[i + 1];
    }
    return dflt;
}

void reject_unknown_args(int argc, char** argv) {
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--endpoint" || a == "--model") {
            if (i + 1 >= argc) fail("ARGUMENT_VALUE_REQUIRED");
            ++i;
            continue;
        }
        fail("UNKNOWN_ARGUMENT");
    }
}

void print_help() {
    std::cout
        << "pcmf-local-model health --endpoint http://127.0.0.1:8080/v1 [--model MODEL]\n"
        << "pcmf-local-model chat   --endpoint http://127.0.0.1:8080/v1 --model MODEL\n"
        << "  chat reads the prompt from stdin. Only loopback HTTP endpoints are accepted.\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--help") {
            print_help();
            return 0;
        }
        if (argc < 2) {
            print_help();
            return 2;
        }
        reject_unknown_args(argc, argv);
        const std::string mode = argv[1];
        const std::string endpoint_raw =
            arg_value(argc, argv, "--endpoint", "http://127.0.0.1:8080/v1");
        const std::string requested_model = arg_value(argc, argv, "--model", "");
        const Endpoint ep = parse_endpoint(endpoint_raw);

        if (mode == "health") {
            const auto ids = model_ids(ep);
            if (!requested_model.empty() && !has_model(ids, requested_model))
                fail("REQUESTED_MODEL_NOT_FOUND");
            J out = J::object();
            out["status"] = J::string("OK");
            out["provider"] = J::string("llama_cpp");
            out["endpoint"] = J::string(endpoint_raw);
            out["model"] = J::string(requested_model.empty() ? ids.front() : requested_model);
            out["memory_authority"] = J::boolean(false);
            out["transport"] = J::string("LOOPBACK_ONLY");
            std::cout << dump(out) << "\n";
            return 0;
        }

        if (mode == "chat") {
            if (requested_model.empty()) fail("MODEL_REQUIRED");
            const auto ids = model_ids(ep);
            if (!has_model(ids, requested_model)) fail("REQUESTED_MODEL_NOT_FOUND");
            const std::string prompt = read_stdin_bounded();

            J req = J::object();
            req["model"] = J::string(requested_model);
            req["stream"] = J::boolean(false);
            J messages = J::array();
            J message = J::object();
            message["role"] = J::string("user");
            message["content"] = J::string(prompt);
            messages.a.push_back(message);
            req["messages"] = messages;

            J res = parse(http(ep, "POST", "/chat/completions", dump(req)));
            if (res.t != J::Obj || !res.has("choices") || res.at("choices").t != J::Arr ||
                res.at("choices").a.empty())
                fail("LOCAL_MODEL_CHAT_INVALID");
            const J& choice = res.at("choices").a.front();
            if (choice.t != J::Obj || !choice.has("message") ||
                choice.at("message").t != J::Obj)
                fail("LOCAL_MODEL_CHAT_INVALID");
            const J& msg = choice.at("message");
            std::string content;
            if (msg.has("content") && msg.at("content").t == J::Str)
                content = msg.at("content").s;
            if (content.empty() && msg.has("reasoning_content") &&
                msg.at("reasoning_content").t == J::Str)
                content = msg.at("reasoning_content").s;
            if (content.empty()) fail("LOCAL_MODEL_EMPTY_RESPONSE");

            J out = J::object();
            out["status"] = J::string("OK");
            out["provider"] = J::string("llama_cpp");
            out["model"] = J::string(requested_model);
            out["content"] = J::string(content);
            out["memory_authority"] = J::boolean(false);
            out["transport"] = J::string("LOOPBACK_ONLY");
            std::cout << dump(out) << "\n";
            return 0;
        }

        fail("UNKNOWN_MODE");
    } catch (const Fail& e) {
        std::cerr << "BLOCKED " << e.what() << "\n";
        return 2;
    } catch (const std::exception&) {
        std::cerr << "BLOCKED LOCAL_MODEL_PROTOCOL_ERROR\n";
        return 2;
    }
}
