#include "l2amc.proxy/l2amc.proxy.hpp"
#include <chrono>
#include <vector>
#include <string>
#include "l2amc.owner.hpp"
#include "utils.hpp"
#include  "ed25519/C++/ed25519.h"
#include  "ed25519/include/ed25519_signature.h"

const std::string MESSAGE_MAGIC = "Bitcoin Signed Message:\n";
const std::string BIND_MSG = "Armonia";
static constexpr eosio::name active_permission{"active"_n};
using namespace amax;
using namespace wasm;

using namespace std;

#define CHECKC(exp, code, msg) \
      { if (!(exp)) eosio::check(false, string("[[") + to_string((int)code) + string("]] ")  \
                                    + string("[[") + _self.to_string() + string("]] ") + msg); }
std::string to_hex( const char* d, uint32_t s ) 
{
    std::string r;
    const char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)d;
    for( uint32_t i = 0; i < s; ++i )
        (r += to_hex[(c[i]>>4)]) += to_hex[(c[i] &0x0f)];
    return r;
}
std::vector<char> encode(const int val,const int minlen) {
    std::vector<char> result;
    // 0-255 的ASCII码值
    int base = 256;
    std::vector<char> chars(base);
    for (int i = 0; i < 256; ++i) {
        chars[i] = static_cast<char>(i);
    }
    //使用模运算符 % 和除法运算符 /，通过将 val 除以 base 来迭代编码过程。每次迭代，我们都会得到一个余数，该余数对应于 chars 向量中的一个字符
    int value = val;
    while (value > 0) {
        auto curcode = chars[value % base];
        result.insert(result.begin(), curcode);
        value /= base;
    }
    // 检查是否需要用零进行填充以达到最小长度 minlen
    int pad_size = minlen - result.size();
    if (pad_size > 0) {
        for (int i = 0; i < pad_size; i++) {
            result.insert(result.begin(), 0);
        }
    }
    return result;
}

std::vector<char> num_to_var_int(const uint64_t x) {
    std::vector<char> result;
    if (x < 253) {
        result.push_back(x);
    } else if (x < 65536) {
        result.push_back((char)253);
        auto encode_bytes = encode(x, 2);
        reverse(encode_bytes.begin(),encode_bytes.end());
        result.insert(result.end(), encode_bytes.begin(), encode_bytes.end());
    } else if (x < 4294967296) {
        result.push_back((char)254);
        auto encode_bytes = encode(x, 4);
        reverse(encode_bytes.begin(),encode_bytes.end());
        result.insert(result.end(), encode_bytes.begin(), encode_bytes.end());
    } else {
        result.push_back((char)255);
        auto encode_bytes = encode(x, 8);
        reverse(encode_bytes.begin(),encode_bytes.end());
        result.insert(result.end(), encode_bytes.begin(), encode_bytes.end());
    }
    
    return result;
}


eosio::checksum256 sha256(const vector<char> data){
    auto sha_1 = eosio::sha256(data.data(),data.size());
    return sha_1;
}
void proxy::init(const name& admin, const name& owner_contract){
    require_auth(_self);
    CHECKC( is_account(admin), err::ACCOUNT_INVALID,"admin account invalid");
    CHECKC( is_account(owner_contract), err::ACCOUNT_INVALID,"owner_contract account invalid");
  
    _gstate.admin = admin; 
    _gstate.owner_contract = owner_contract;
}
void proxy::activate( const name& account, 
                    const string& btc_pub_key,
                    const eosio::signature& signature,
                    const public_key& temp_amc_pub){
    require_auth(_gstate.admin);

    auto msg_packed = pack(temp_amc_pub);
    auto packed_data = pack(msg_packed_t(MESSAGE_MAGIC,to_hex(msg_packed.data(),msg_packed.size())));
    
    auto public_key = recover_key(sha256(packed_data),signature);

    auto accs = l2amc_owner::l2amc_account_t::idx_t( _gstate.owner_contract, L2AMC_BTC_NAME.value);
    auto itr = accs.find(account.value);
    if ( itr == accs.end()){
        l2amc_owner::bind_action newaccount_act(_gstate.owner_contract,{ {get_self(), ACTIVE_PERM} });
        newaccount_act.send(_self,L2AMC_BTC_NAME,btc_pub_key,account,L2AMC_BTC_NAME,public_key);
    }else {
        CHECKC( itr -> xchain_pubkey == btc_pub_key, err::PARAM_ERROR,"l2amc_acct already exist l2amc pubkey: " + btc_pub_key )
        CHECKC( itr -> recovered_public_key == public_key, err::PARAM_ERROR,"l2amc_acct already exist l2amc pubkey: " + account.to_string() )
    }
    
    l2amc_owner::updateauth_action setauth_act(_gstate.owner_contract,{ {get_self(), ACTIVE_PERM} });
    setauth_act.send(_self,account,temp_amc_pub);
}


void proxy::submitaction(const name& account, const vector<char> packed_action,const eosio::signature& sign){
    
    require_auth(account);
    string msg = to_hex(packed_action.data(),packed_action.size());

    vector<char> packed = pack(MESSAGE_MAGIC);
    vector<char> msg_packed = {num_to_var_int(msg.size())};
    
    for (auto it = msg.begin(); it != msg.end(); ++it) {
        msg_packed.push_back(*it);
    }
    packed.insert(packed.end(),msg_packed.begin(),msg_packed.end());
    auto recover_pub_key =  recover_key( sha256(packed), sign);
    auto accs = l2amc_owner::l2amc_account_t::idx_t( _gstate.owner_contract, L2AMC_BTC_NAME.value);
    
    auto itr = accs.find(account.value);
    CHECKC( itr != accs.end(), err::RECORD_NOT_FOUND,"[proxy] account not found")
    CHECKC( itr-> recovered_public_key == recover_pub_key, err::DATA_MISMATCH,"Public key mismatch")
    unpacked_action_t unpacked_action = unpack<unpacked_action_t>(packed_action.data(),packed_action.size());
    CHECKC( unpacked_action.actions.size() > 0 , err::OVERSIZED,"There are no executable actions")

    vector<eosio::action> actions;
    for ( auto at : unpacked_action.actions){
        eosio::action send_action;
        send_action.account = at.account;
        send_action.name = at.name;
        send_action.data = at.data;
        send_action.authorization.emplace_back(permission_level{ account, active_permission });
        actions.push_back(send_action);
        
    }
    l2amc_owner::execaction_action exec_act(_gstate.owner_contract,{ {get_self(), ACTIVE_PERM} });
    exec_act.send( _self,L2AMC_BTC_NAME, account , actions, unpacked_action.nonce);

}

template<typename CharT>
static std::string to_hex(const CharT* d, uint32_t s) {
  std::string r;
  const char* to_hex="0123456789abcdef";
  uint8_t* c = (uint8_t*)d;
  for( uint32_t i = 0; i < s; ++i ) {
    (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
  }
  return r;
}

    #define ed25519_public_key_size     32
    #define ed25519_secret_key_size     32
    #define ed25519_private_key_size    64
    #define ed25519_signature_size      64

void proxy::test( const vector<char> packed_action,const eosio::signature& sign){
    
    // // CHECKC(false, err::RECORD_EXISTING,"test esrror");

    // eosio::checksum256 str= sha256(packed_action);
    // string sum= to_hex(&str, sizeof(str) );
    // // auto recover_pub_key =  recover_key( sha256(packed), sign);
    // CHECKC(false, err::RECORD_EXISTING,sum);

        unsigned char sk1[32] = 
    { 0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
        0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb };
    unsigned char pk1[ed25519_public_key_size] = 
    { 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
        0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
    unsigned char msg1[] = { 0x72 };
    unsigned char msg1_sig[ed25519_signature_size] = {
        0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
        0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
        0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
        0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
    };

    signature_test(sk1, pk1, msg1, sizeof(msg1), msg1_sig);

}

void proxy::test2(){
    unsigned char sk1[32] = 
    { 0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
        0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb };
    unsigned char pk1[ed25519_public_key_size] = 
    { 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
        0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
    unsigned char msg1[] = { 0x72 };
    unsigned char msg1_sig[ed25519_signature_size] = {
        0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
        0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
        0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
        0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
    };

    signature_test(sk1, pk1, msg1, sizeof(msg1), msg1_sig);

}
typedef unsigned char       U8;
typedef signed   char       S8;
typedef uint16_t            U16;
typedef int16_t             S16;
typedef uint32_t            U32;
typedef int32_t             S32;
typedef uint64_t            U64;
typedef int64_t             S64;

extern void ecp_TrimSecretKey(U8 *X);
const unsigned char BasePoint[32] = {9};

unsigned char secret_blind[32] =
{
    0xea,0x30,0xb1,0x6d,0x83,0x9e,0xa3,0x1a,0x86,0x34,0x01,0x9d,0x4a,0xf3,0x36,0x93,
    0x6d,0x54,0x2b,0xa1,0x63,0x03,0x93,0x85,0xcc,0x03,0x0a,0x7d,0xe1,0xae,0xa7,0xbb
};

int32_t ecp_PrintHexBytes( const char *name,  const U8 *data, U32 size)
{
    printf("%s = 0x", name);
    while (size > 0) printf("%02X", data[--size]);
    printf("\n");
    return 1;
}


int32_t ecp_PrintBytes(const char *name, const U8 *data, U32 size)
{
    U32 i;
    printf("\nstatic const unsigned char %s[%d] =\n  { 0x%02X", name, size, *data++);
    for (i = 1; i < size; i++)
    {
        if ((i & 15) == 0)
            printf(",\n    0x%02X", *data++);
        else
            printf(",0x%02X", *data++);
    }
    printf(" };\n");
    return 1;
}

int proxy::signature_test(
    const unsigned char *sk, 
    const unsigned char *expected_pk, 
    const unsigned char *msg, size_t size, 
    const unsigned char *expected_sig)
{
   int rc = 0;
    unsigned char sig[ed25519_signature_size];
    unsigned char pubKey[ed25519_public_key_size];
    unsigned char privKey[ed25519_private_key_size];
    void *blinding = ed25519_Blinding_Init(0, secret_blind, sizeof(secret_blind));

    printf("\n-- ed25519 -- sign/verify test ---------------------------------\n");
    printf("\n-- CreateKeyPair --\n");
    ed25519_CreateKeyPair(pubKey, privKey, 0, sk);
    ecp_PrintHexBytes("secret_key", sk, ed25519_secret_key_size);
    ecp_PrintHexBytes("public_key", pubKey, ed25519_public_key_size);
    ecp_PrintBytes("private_key", privKey, ed25519_private_key_size);

    if (expected_pk && memcmp(pubKey, expected_pk, ed25519_public_key_size) != 0)
    {
        rc++;
        printf("ed25519_CreateKeyPair() FAILED!!\n");
        ecp_PrintHexBytes("Expected_pk", expected_pk, ed25519_public_key_size);
    }

    printf("-- Sign/Verify --\n");
    ed25519_SignMessage(sig, privKey, 0, msg, size);
    ecp_PrintBytes("message", msg, (U32)size);
    ecp_PrintBytes("signature", sig, ed25519_signature_size);
    if (expected_sig && memcmp(sig, expected_sig, ed25519_signature_size) != 0)
    {
        rc++;
        printf("Signature generation FAILED!!\n");
        ecp_PrintBytes("Calculated", sig, ed25519_signature_size);
        ecp_PrintBytes("ExpectedSig", expected_sig, ed25519_signature_size);
    }

    if (!ed25519_VerifySignature(sig, pubKey, msg, size))
    {
        rc++;
        printf("Signature verification FAILED!!\n");
        ecp_PrintBytes("sig", sig, ed25519_signature_size);
        ecp_PrintBytes("pk", pubKey, ed25519_public_key_size);
    }

    printf("\n-- ed25519 -- sign/verify test w/blinding ----------------------\n");
    printf("\n-- CreateKeyPair --\n");
    ed25519_CreateKeyPair(pubKey, privKey, blinding, sk);
    ecp_PrintHexBytes("secret_key", sk, ed25519_secret_key_size);
    ecp_PrintHexBytes("public_key", pubKey, ed25519_public_key_size);
    ecp_PrintBytes("private_key", privKey, ed25519_private_key_size);

    if (expected_pk && memcmp(pubKey, expected_pk, ed25519_public_key_size) != 0)
    {
        rc++;
        printf("ed25519_CreateKeyPair() FAILED!!\n");
        ecp_PrintHexBytes("Expected_pk", expected_pk, ed25519_public_key_size);
    }

    printf("-- Sign/Verify --\n");
    ed25519_SignMessage(sig, privKey, blinding, msg, size);
    ecp_PrintBytes("message", msg, (U32)size);
    ecp_PrintBytes("signature", sig, ed25519_signature_size);
    if (expected_sig && memcmp(sig, expected_sig, ed25519_signature_size) != 0)
    {
        rc++;
        printf("Signature generation FAILED!!\n");
        ecp_PrintBytes("Calculated", sig, ed25519_signature_size);
        ecp_PrintBytes("ExpectedSig", expected_sig, ed25519_signature_size);
    }

    if (!ed25519_VerifySignature(sig, pubKey, msg, size))
    {
        rc++;
        printf("Signature verification FAILED!!\n");
        ecp_PrintBytes("sig", sig, ed25519_signature_size);
        ecp_PrintBytes("pk", pubKey, ed25519_public_key_size);
    }

    if (rc == 0)
    {
        printf("  ++ Signature Verified Successfully. ++\n");
    }

    ed25519_Blinding_Finish(blinding);
    return rc;
}