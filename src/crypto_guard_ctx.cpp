#include "crypto_guard_ctx.h"
#include <memory>


namespace CryptoGuard {

struct CryptoGuardCtx::Impl{
    void Encrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password){

    }
    void Decrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password){

    }
    std::string CalculateChecksum(std::iostream &inStream){
        return "NOT IMPLEMENTED";
    }
};

CryptoGuardCtx::CryptoGuardCtx():pImpl_(std::make_unique<Impl>()){};
CryptoGuardCtx::~CryptoGuardCtx()=default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
    pImpl_->Encrypt(inStream, outStream, password);
};
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
    pImpl_->Decrypt(inStream, outStream, password);
};
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream){return pImpl_->CalculateChecksum(inStream);};
    
}  // namespace CryptoGuard
