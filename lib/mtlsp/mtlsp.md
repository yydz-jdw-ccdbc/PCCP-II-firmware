1. client在烧录时确定server公钥$$S_{pub}$$，同时双方均使用libsodium库进行密码学操作。
2. 建立TCP连接
3. client发送256位随机数$$client\_random$$
4. server收到后生成ECDH公私钥对$$(Q_s=d_sP,d_s)$$，发送256位随机数$$server\_random$$、公钥$$Q_s$$和$$Sig_{S_{sec}}(H(Q_s,client\_random,server\_random))$$
7. client验证签名后确信$$Q_s,client\_random,server\_random$$新鲜无误，确定临时ECDH公私钥对($$Q_c=d_sP, d_c$$)，发送$$BOX_{S_{pub}}(Q_c,client\_random,server\_random)$$，否则中断连接
8. server确认$$client\_random,server\_random$$无误，发送$$BOX_{Q_c}(OK)$$，否则发送$$BOX_{Q_c}(NotOK)$$并断开链接
9. 双方在本地确认预主密钥$$Z=d_sQ_c=d_cQ_s$$，256位主密钥$$M=H(Z,client\_random,server\_random)$$
10. client确定设备原始指纹$$fg$$（约50K大小的图片）, 发送$$E_M(fg)$$
11. 若$$fg$$合法，发送$$E_M(OK)$$，否则发送$$E_M(NotOK)$$
12. 开始加密消息传送
