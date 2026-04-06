"""QPACK static table (RFC 9204 Appendix A).

99 entries, 0-indexed. Each entry is a (name, value) tuple of bytes.
Ported from pylsqpack/vendor/ls-qpack/lsqpack.c:105-209.
"""

STATIC_TABLE: tuple[tuple[bytes, bytes], ...] = (
    (b":authority", b""),                                                  # 0
    (b":path", b"/"),                                                      # 1
    (b"age", b"0"),                                                        # 2
    (b"content-disposition", b""),                                          # 3
    (b"content-length", b"0"),                                             # 4
    (b"cookie", b""),                                                       # 5
    (b"date", b""),                                                         # 6
    (b"etag", b""),                                                         # 7
    (b"if-modified-since", b""),                                            # 8
    (b"if-none-match", b""),                                                # 9
    (b"last-modified", b""),                                                # 10
    (b"link", b""),                                                         # 11
    (b"location", b""),                                                     # 12
    (b"referer", b""),                                                      # 13
    (b"set-cookie", b""),                                                   # 14
    (b":method", b"CONNECT"),                                              # 15
    (b":method", b"DELETE"),                                               # 16
    (b":method", b"GET"),                                                  # 17
    (b":method", b"HEAD"),                                                 # 18
    (b":method", b"OPTIONS"),                                              # 19
    (b":method", b"POST"),                                                 # 20
    (b":method", b"PUT"),                                                  # 21
    (b":scheme", b"http"),                                                 # 22
    (b":scheme", b"https"),                                                # 23
    (b":status", b"103"),                                                  # 24
    (b":status", b"200"),                                                  # 25
    (b":status", b"304"),                                                  # 26
    (b":status", b"404"),                                                  # 27
    (b":status", b"503"),                                                  # 28
    (b"accept", b"*/*"),                                                   # 29
    (b"accept", b"application/dns-message"),                               # 30
    (b"accept-encoding", b"gzip, deflate, br"),                            # 31
    (b"accept-ranges", b"bytes"),                                          # 32
    (b"access-control-allow-headers", b"cache-control"),                   # 33
    (b"access-control-allow-headers", b"content-type"),                    # 34
    (b"access-control-allow-origin", b"*"),                                # 35
    (b"cache-control", b"max-age=0"),                                      # 36
    (b"cache-control", b"max-age=2592000"),                                # 37
    (b"cache-control", b"max-age=604800"),                                 # 38
    (b"cache-control", b"no-cache"),                                       # 39
    (b"cache-control", b"no-store"),                                       # 40
    (b"cache-control", b"public, max-age=31536000"),                       # 41
    (b"content-encoding", b"br"),                                          # 42
    (b"content-encoding", b"gzip"),                                        # 43
    (b"content-type", b"application/dns-message"),                         # 44
    (b"content-type", b"application/javascript"),                          # 45
    (b"content-type", b"application/json"),                                # 46
    (b"content-type", b"application/x-www-form-urlencoded"),               # 47
    (b"content-type", b"image/gif"),                                       # 48
    (b"content-type", b"image/jpeg"),                                      # 49
    (b"content-type", b"image/png"),                                       # 50
    (b"content-type", b"text/css"),                                        # 51
    (b"content-type", b"text/html; charset=utf-8"),                        # 52
    (b"content-type", b"text/plain"),                                      # 53
    (b"content-type", b"text/plain;charset=utf-8"),                        # 54
    (b"range", b"bytes=0-"),                                               # 55
    (b"strict-transport-security", b"max-age=31536000"),                   # 56
    (b"strict-transport-security",
     b"max-age=31536000; includesubdomains"),                              # 57
    (b"strict-transport-security",
     b"max-age=31536000; includesubdomains; preload"),                     # 58
    (b"vary", b"accept-encoding"),                                         # 59
    (b"vary", b"origin"),                                                  # 60
    (b"x-content-type-options", b"nosniff"),                               # 61
    (b"x-xss-protection", b"1; mode=block"),                               # 62
    (b":status", b"100"),                                                  # 63
    (b":status", b"204"),                                                  # 64
    (b":status", b"206"),                                                  # 65
    (b":status", b"302"),                                                  # 66
    (b":status", b"400"),                                                  # 67
    (b":status", b"403"),                                                  # 68
    (b":status", b"421"),                                                  # 69
    (b":status", b"425"),                                                  # 70
    (b":status", b"500"),                                                  # 71
    (b"accept-language", b""),                                             # 72
    (b"access-control-allow-credentials", b"FALSE"),                       # 73
    (b"access-control-allow-credentials", b"TRUE"),                        # 74
    (b"access-control-allow-headers", b"*"),                               # 75
    (b"access-control-allow-methods", b"get"),                             # 76
    (b"access-control-allow-methods", b"get, post, options"),              # 77
    (b"access-control-allow-methods", b"options"),                         # 78
    (b"access-control-expose-headers", b"content-length"),                 # 79
    (b"access-control-request-headers", b"content-type"),                  # 80
    (b"access-control-request-method", b"get"),                            # 81
    (b"access-control-request-method", b"post"),                           # 82
    (b"alt-svc", b"clear"),                                                # 83
    (b"authorization", b""),                                               # 84
    (b"content-security-policy",
     b"script-src 'none'; object-src 'none'; base-uri 'none'"),            # 85
    (b"early-data", b"1"),                                                 # 86
    (b"expect-ct", b""),                                                   # 87
    (b"forwarded", b""),                                                   # 88
    (b"if-range", b""),                                                    # 89
    (b"origin", b""),                                                      # 90
    (b"purpose", b"prefetch"),                                             # 91
    (b"server", b""),                                                      # 92
    (b"timing-allow-origin", b"*"),                                        # 93
    (b"upgrade-insecure-requests", b"1"),                                  # 94
    (b"user-agent", b""),                                                  # 95
    (b"x-forwarded-for", b""),                                             # 96
    (b"x-frame-options", b"deny"),                                         # 97
    (b"x-frame-options", b"sameorigin"),                                   # 98
)

STATIC_TABLE_SIZE = len(STATIC_TABLE)  # 99
