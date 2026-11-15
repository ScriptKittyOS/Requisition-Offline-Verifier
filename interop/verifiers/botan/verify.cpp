// Botan ML-DSA-87 (pure, external interface) over a cases file. usage: verify CASES.tsv
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
#include <botan/build.h>
#include <botan/dilithium.h>
#include <botan/pk_options.h>
#include <botan/pubkey.h>
#include <botan/version.h>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

static std::optional<std::vector<uint8_t>> unhex(const std::string& s) {
   std::vector<uint8_t> out;
   if(s == "-") return out;
   if(s.empty() || s.size() % 2) return std::nullopt;
   auto hv = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
   for(size_t i = 0; i < s.size(); i += 2) {
      int h = hv(s[i]), l = hv(s[i + 1]);
      if(h < 0 || l < 0) return std::nullopt;
      out.push_back(static_cast<uint8_t>(h * 16 + l));
   }
   return out;
}

static bool verify(const std::vector<uint8_t>& pk, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& msg,
                   const std::vector<uint8_t>& ctx) {
   try {
      Botan::Dilithium_PublicKey key(pk, Botan::DilithiumMode(Botan::DilithiumMode::ML_DSA_8x7));
      Botan::PK_Signature_Options opts;
      if(!ctx.empty()) opts = opts.with_context(std::span<const uint8_t>(ctx));
      Botan::PK_Verifier v(key, opts);
      return v.verify_message(msg, sig);
   } catch(const std::exception&) {
      return false;
   }
}

int main(int argc, char** argv) {
   if(argc != 2) { std::cerr << "usage: verify CASES.tsv\n"; return 2; }
   std::ifstream f(argv[1]);
   if(!f) { std::cerr << "cannot read " << argv[1] << "\n"; return 2; }
   std::string line;
   int n = 0;
   std::vector<std::string> bad;
   while(std::getline(f, line)) {
      if(line.empty()) continue;
      std::vector<std::string> p;
      size_t st = 0;
      for(;;) {
         size_t t = line.find('\t', st);
         if(t == std::string::npos) { p.push_back(line.substr(st)); break; }
         p.push_back(line.substr(st, t - st));
         st = t + 1;
      }
      if(p.size() != 6) { std::cerr << "bad line\n"; return 2; }
      auto pk = unhex(p[1]), sig = unhex(p[2]), msg = unhex(p[3]), ctx = unhex(p[4]);
      if(!pk || !sig || !msg || !ctx) { std::cerr << "bad hex in case " << p[0] << "\n"; return 2; }
      if(p[5] != "0" && p[5] != "1") { std::cerr << "bad expected result in case " << p[0] << "\n"; return 2; }
      bool got = verify(*pk, *sig, *msg, *ctx);
      n++;
      if(got != (p[5] == "1")) bad.push_back(p[0]);
   }
   if(f.bad()) { std::cerr << "read error\n"; return 2; }
   if(n == 0) { std::cerr << "no cases\n"; return 2; }
   std::string ids;
   for(size_t i = 0; i < bad.size(); i++) ids += (i ? ", " : "") + bad[i];
   std::cout << "Botan " << Botan::short_version_string() << ": " << n << " cases, " << bad.size()
             << " disagree with the expected result [" << ids << "]\n";
   return bad.empty() ? 0 : 1;
}
