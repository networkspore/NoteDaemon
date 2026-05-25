// include/tls_transport.h
// TLS transport wrapper for TCP connections using OpenSSL

#ifndef TLS_TRANSPORT_H
#define TLS_TRANSPORT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <syslog.h>
#include <string>
#include <memory>
#include <vector>
#include <mutex>

namespace TLS {

/**
 * TLS context configuration
 */
struct TLSConfig {
    std::string cert_file;
    std::string key_file;
    std::string ca_file;
    bool require_client_cert = false;
};

/**
 * TLS Context - manages SSL_CTX lifecycle
 */
class TLSContext {
public:
    explicit TLSContext(const TLSConfig& config) : config_(config) {}
    
    ~TLSContext() {
        if (ctx_) {
            SSL_CTX_free(ctx_);
        }
    }
    
    // Non-copyable
    TLSContext(const TLSContext&) = delete;
    TLSContext& operator=(const TLSContext&) = delete;
    
    /**
     * Initialize the TLS context
     * @return true on success
     */
    bool initialize() {
        // Create SSL context (TLS 1.2+)
        ctx_ = SSL_CTX_new(TLS_method());
        if (!ctx_) {
            log_ssl_error("SSL_CTX_new failed");
            return false;
        }
        
        // Set minimum TLS version to 1.2
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        
        // Load server certificate
        if (SSL_CTX_use_certificate_file(ctx_, config_.cert_file.c_str(), 
                                          SSL_FILETYPE_PEM) != 1) {
            log_ssl_error("Failed to load certificate: " + config_.cert_file);
            return false;
        }
        
        // Load private key
        if (SSL_CTX_use_PrivateKey_file(ctx_, config_.key_file.c_str(),
                                         SSL_FILETYPE_PEM) != 1) {
            log_ssl_error("Failed to load private key: " + config_.key_file);
            return false;
        }
        
        // Verify private key matches certificate
        if (SSL_CTX_check_private_key(ctx_) != 1) {
            log_ssl_error("Private key does not match certificate");
            return false;
        }
        
        // Load CA certificate for client verification (if provided)
        if (!config_.ca_file.empty()) {
            if (SSL_CTX_load_verify_locations(ctx_, config_.ca_file.c_str(),
                                               nullptr) != 1) {
                log_ssl_error("Failed to load CA file: " + config_.ca_file);
                return false;
            }
            
            // If client cert is required, set verify mode
            if (config_.require_client_cert) {
                SSL_CTX_set_verify(ctx_, 
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                    nullptr);
                syslog(LOG_INFO, "TLS: Client certificate verification enabled (mTLS)");
            }
        }
        
        // Set cipher list (strong ciphers only)
        if (SSL_CTX_set_cipher_list(ctx_, 
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256") != 1) {
            log_ssl_error("Failed to set cipher list");
            return false;
        }
        
        initialized_ = true;
        syslog(LOG_INFO, "TLS context initialized (cert=%s, key=%s)",
               config_.cert_file.c_str(), config_.key_file.c_str());
        
        return true;
    }
    
    bool is_initialized() const { return initialized_; }
    SSL_CTX* get() { return ctx_; }
    
private:
    TLSConfig config_;
    SSL_CTX* ctx_ = nullptr;
    bool initialized_ = false;
    
    static void log_ssl_error(const std::string& msg) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        syslog(LOG_ERR, "TLS: %s: %s", msg.c_str(), buf);
    }
};

/**
 * TLS Connection - wraps a single SSL connection
 */
class TLSConnection {
public:
    TLSConnection(SSL_CTX* ctx, int fd) : fd_(fd) {
        ssl_ = SSL_new(ctx);
    }
    
    ~TLSConnection() {
        if (ssl_) {
            SSL_free(ssl_);
        }
    }
    
    // Non-copyable
    TLSConnection(const TLSConnection&) = delete;
    TLSConnection& operator=(const TLSConnection&) = delete;
    
    /**
     * Perform TLS handshake (server side)
     * @return true on success
     */
    bool accept() {
        if (!ssl_) return false;
        
        SSL_set_fd(ssl_, fd_);
        
        int ret = SSL_accept(ssl_);
        if (ret != 1) {
            int err = SSL_get_error(ssl_, ret);
            syslog(LOG_ERR, "TLS handshake failed (error=%d)", err);
            log_ssl_error("SSL_accept");
            return false;
        }
        
        // Log peer certificate info if available
        X509* peer_cert = SSL_get_peer_certificate(ssl_);
        if (peer_cert) {
            char* subject = X509_NAME_oneline(X509_get_subject_name(peer_cert), nullptr, 0);
            char* issuer = X509_NAME_oneline(X509_get_issuer_name(peer_cert), nullptr, 0);
            syslog(LOG_INFO, "TLS: Peer cert subject=%s issuer=%s",
                   subject ? subject : "none",
                   issuer ? issuer : "none");
            OPENSSL_free(subject);
            OPENSSL_free(issuer);
            X509_free(peer_cert);
        }
        
        const char* cipher = SSL_get_cipher_name(ssl_);
        const char* version = SSL_get_version(ssl_);
        syslog(LOG_INFO, "TLS: Connection established (%s, %s)", version, cipher);
        
        established_ = true;
        return true;
    }
    
    /**
     * Read data from TLS connection
     * @return bytes read, 0 on EOF, -1 on error
     */
    int read(void* buf, int len) {
        if (!established_) return -1;
        return SSL_read(ssl_, buf, len);
    }
    
    /**
     * Write data to TLS connection
     * @return bytes written, -1 on error
     */
    int write(const void* buf, int len) {
        if (!established_) return -1;
        return SSL_write(ssl_, buf, len);
    }
    
    /**
     * Shutdown TLS connection gracefully
     */
    void shutdown() {
        if (ssl_ && established_) {
            SSL_shutdown(ssl_);
            established_ = false;
        }
    }
    
    bool is_established() const { return established_; }
    SSL* get() { return ssl_; }
    
private:
    SSL* ssl_ = nullptr;
    int fd_ = -1;
    bool established_ = false;
    
    void log_ssl_error(const std::string& msg) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        syslog(LOG_ERR, "TLS: %s: %s", msg.c_str(), buf);
    }
};

/**
 * IP allowlist checker
 */
class IPAllowlist {
public:
    IPAllowlist() = default;
    
    /**
     * Parse CIDR notation (e.g., "192.168.1.0/24")
     * @return true if parsing succeeded
     */
    static bool parse_cidr(const std::string& cidr, uint32_t& network, uint32_t& mask) {
        size_t slash = cidr.find('/');
        if (slash == std::string::npos) {
            // Single IP
            struct in_addr addr;
            if (inet_pton(AF_INET, cidr.c_str(), &addr) != 1) {
                return false;
            }
            network = ntohl(addr.s_addr);
            mask = 0xFFFFFFFF;
            return true;
        }
        
        // CIDR notation
        std::string ip = cidr.substr(0, slash);
        std::string prefix_str = cidr.substr(slash + 1);
        
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
            return false;
        }
        
        int prefix_len;
        try {
            prefix_len = std::stoi(prefix_str);
        } catch (...) {
            return false;
        }
        
        if (prefix_len < 0 || prefix_len > 32) {
            return false;
        }
        
        network = ntohl(addr.s_addr);
        mask = prefix_len == 0 ? 0 : (0xFFFFFFFF << (32 - prefix_len));
        
        return true;
    }
    
    /**
     * Add an IP or CIDR range to the allowlist
     */
    bool add(const std::string& cidr) {
        uint32_t network, mask;
        if (!parse_cidr(cidr, network, mask)) {
            syslog(LOG_ERR, "IPAllowlist: Invalid CIDR: %s", cidr.c_str());
            return false;
        }
        entries_.push_back({network, mask, cidr});
        syslog(LOG_INFO, "IPAllowlist: Added %s", cidr.c_str());
        return true;
    }
    
    /**
     * Check if an IP address is allowed
     * @param ip_str IP address in dotted notation
     * @return true if allowed (or if allowlist is empty)
     */
    bool is_allowed(const std::string& ip_str) const {
        if (entries_.empty()) {
            return true;  // No allowlist = allow all
        }
        
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
            syslog(LOG_WARNING, "IPAllowlist: Invalid IP: %s", ip_str.c_str());
            return false;
        }
        
        uint32_t ip = ntohl(addr.s_addr);
        
        for (const auto& entry : entries_) {
            if ((ip & entry.mask) == (entry.network & entry.mask)) {
                return true;
            }
        }
        
        return false;
    }
    
    bool empty() const { return entries_.empty(); }
    
    size_t size() const { return entries_.size(); }
    
private:
    struct Entry {
        uint32_t network;
        uint32_t mask;
        std::string original;
    };
    
    std::vector<Entry> entries_;
};

} // namespace TLS

#endif // TLS_TRANSPORT_H
