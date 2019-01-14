## what is SPHINCS <sup>+</sup>

[official website](https://sphincs.org/index.html)

SPHINCS+ is a stateless hash-based signature scheme, which was submitted to the NIST post-quantum crypto project. The design advances the SPHINCS signature scheme, which was presented at EUROCRYPT 2015. It incorporates multiple improvements, specifically aimed at reducing signature size. For a quick overview of the changes from SPHINCS to SPHINCS+ see the blog post by Andreas Hülsing. The submission proposes three different signature schemes:

- SPHINCS <sup>+</sup> - SHAKE256
- SPHINCS <sup>+</sup> - SHA-256
- SPHINCS <sup>+</sup> - Haraka

These signature schemes are obtained by instantiating the SPHINCS+ construction with SHAKE256, SHA-256, and Haraka, respectively.

SPHINCS <sup>+</sup> 是一种无状态的基于散列的签名方案，已提交给NIST后量子加密项目。该设计推进了SPHINCS签名方案，该方案于2015年EUROCRYPT上发布。它包含多项改进，专门用于减少签名大小。对于从SPHINCS到SPHINCS变化的快速概述+ 看到由AndreasHülsing博客文章。提交提出了三种不同的签名方案：

- SPHINCS <sup>+</sup> - SHAKE256
- SPHINCS <sup>+</sup> - SHA-256
- SPHINCS <sup>+</sup> - Haraka

这些签名方案是通过分别使用SHAKE256，SHA-256和Haraka 实例化SPHINCS +结构而获得的。

SPHINCS-256 is a high-security post-quantum stateless hash-based signature scheme that signs hundreds of messages per second on a modern 4-core 3.5GHz Intel CPU. Signatures are 41 KB, public keys are 1 KB, and private keys are 1 KB. SPHINCS-256 is designed to provide long-term 2128 security even against attackers equipped with quantum computers. Unlike most hash-based signature schemes, SPHINCS-256 is stateless, allowing it to be a drop-in replacement for current signature schemes.

SPHINCS-256是一种高安全性的基于量子无状态散列的签名方案，可在现代4核3.5GHz Intel CPU上每秒签署数百条消息。签名为41 KB，公钥为1 KB，私钥为1 KB。SPHINCS-256旨在为配备量子计算机的攻击者提供长期的$2^{128}$安全性。与大多数基于散列的签名方案不同，SPHINCS-256是无状态的，允许它成为当前签名方案的直接替代品。

