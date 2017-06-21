import * as crypto from 'crypto';
import * as XMLParser from 'xml2js';


const buildXML = new XMLParser.Builder({
    rootName: 'xml',
    cdata: true,
    headless: true,
    renderOpts: {indent: ' ', pretty: true},
});

export default class WxCrypto {
    private token: string;
    private appid: string;
    private aesKey: Buffer;
    private iv: Buffer;

    /**
     * 构造方法
     * @param token
     * @param appid
     * @param encodingAESKey
     */
    constructor(token: string, appid: string, encodingAESKey: string) {
        this.token = token;
        this.appid = appid;
        this.aesKey = new Buffer(`${encodingAESKey}=`, 'base64');
        this.iv = this.aesKey.slice(0, 16);
    }

    /**
     * xml转换为json
     * @param xml
     * @returns {Promise}
     */
    public static xml2json(xml: string): Promise<any> {
        return new Promise((resolve, reject) => {
            XMLParser.parseString(xml, {
                rootName: 'xml',
                cdata: true,
                headless: true,
                renderOpts: {indent: ' ', pretty: true},
            }, (e, data) => {
                if (e) {
                    return reject(e);
                }
                const result: any = {};
                Object.keys(data.xml).forEach(key => {
                    result[key] = data.xml[key][0];
                });
                resolve(result);
            });
        });
    }

    /**
     * 消息解密
     * @param msgSignature
     * @param timestamp
     * @param nonce
     * @param xml
     * @returns {Promise}
     */
    public async decryptMsg(msgSignature: string, timestamp: number, nonce: string, xml: string): Promise<any> {
        const data = await WxCrypto.xml2json(xml);
        const msgEncrypt = data.Encrypt;
        if (this.getSignature(timestamp, nonce, msgEncrypt) !== msgSignature) {
            throw new Error('msgSignature is not invalid');
        }
        const decryptedMessage = this.decrypt(msgEncrypt);
        return new Promise((resolve, reject) => {
            XMLParser.parseString(decryptedMessage, {explicitArray: false}, (e, result) => e ? reject(e) : resolve(result.xml));
        });
    }

    /**
     * 消息加密
     * @param replyMsg
     * @param opts
     * @returns {string}
     */
    public encryptMsg(replyMsg: any, opts: any) {
        const result: any = {};
        const options = opts || {};
        result.Encrypt = this.encrypt(replyMsg);
        result.Nonce = options.nonce || parseInt((Math.random() * 100000000000).toString(), 10);
        result.TimeStamp = options.timestamp || new Date().getTime();
        result.MsgSignature = this.getSignature(result.TimeStamp, result.Nonce, result.Encrypt);
        return buildXML.buildObject(result);
    }

    public encrypt(xmlMsg: any) {
        const random16 = new Buffer(parseInt((Math.random() * 100000000000).toString(), 10));
        const msg = new Buffer(xmlMsg);
        const msgLength = new Buffer(4);
        msgLength.writeUInt32BE(msg.length, 0);
        const corpId = new Buffer(this.appid);
        const rawMsg = Buffer.concat([random16, msgLength, msg, corpId]);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, this.iv);
        const cipheredMsg = Buffer.concat([cipher.update(rawMsg), cipher.final()]);
        return cipheredMsg.toString('base64');
    }

    public decrypt(str: string) {
        const aesCipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, this.iv);
        aesCipher.setAutoPadding(false);
        let decipheredBuff = Buffer.concat([aesCipher.update(str, 'base64'), aesCipher.final()]);
        decipheredBuff = WxCrypto.PKCS7Decoder(decipheredBuff);
        const lenNetOrderCorpid = decipheredBuff.slice(16);
        const msgLen = lenNetOrderCorpid.slice(0, 4).readUInt32BE(0);
        const result = lenNetOrderCorpid.slice(4, msgLen + 4).toString();
        const appId = lenNetOrderCorpid.slice(msgLen + 4).toString();
        if (appId !== this.appid) {
            throw new Error('appId is invalid');
        }
        return result;
    }

    public getSignature(timestamp: number, nonce: string, encrypt: string) {
        const signature = [this.token, timestamp, nonce, encrypt].sort().join('');
        const sha1 = crypto.createHash('sha1');
        sha1.update(signature);
        return sha1.digest('hex');
    }

    public static PKCS7Decoder(buff: Buffer) {
        let pad = buff[buff.length - 1];
        if (pad < 1 || pad > 32) {
            pad = 0;
        }
        return buff.slice(0, buff.length - pad);
    }

    public static PKCS7Encoder(buff: Buffer) {
        const blockSize = 32;
        const strSize = buff.length;
        const amountToPad = blockSize - (strSize % blockSize);
        const pad = new Buffer(amountToPad - 1);
        pad.fill(String.fromCharCode(amountToPad));
        return Buffer.concat([buff, pad]);
    }
}