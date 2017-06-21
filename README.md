# wxcrypto-nodejs
微信消息加解密解决方案

## 安装
`npm install @xialeistudio/wxcrypto`

## 使用
```typescript
import WxCrypto from '@xialeistudio/wxcrypto';

const xml = 'xxx';
const wechat = new WxCrypto('token', 'appid', 'encodingAesKey');
const json = await wechat.decryptMsg(msg_signature, timestamp, nonce, xml); // 消息解密
const encrypted = wechat.encryptMsg('xxx');
```