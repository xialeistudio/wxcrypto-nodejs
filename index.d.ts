/// <reference types="node" />
export default class WxCrypto {
    private token;
    private appid;
    private aesKey;
    private iv;
    /**
     * 构造方法
     * @param token
     * @param appid
     * @param encodingAESKey
     */
    constructor(token: string, appid: string, encodingAESKey: string);
    /**
     * xml转换为json
     * @param xml
     * @returns {Promise}
     */
    static xml2json(xml: string): Promise<any>;
    /**
     * 消息解密
     * @param msgSignature
     * @param timestamp
     * @param nonce
     * @param xml
     * @returns {Promise}
     */
    decryptMsg(msgSignature: string, timestamp: number, nonce: string, xml: string): Promise<any>;
    /**
     * 消息加密
     * @param replyMsg
     * @param opts
     * @returns {string}
     */
    encryptMsg(replyMsg: any, opts: any): string;
    encrypt(xmlMsg: any): string;
    decrypt(str: string): string;
    getSignature(timestamp: number, nonce: string, encrypt: string): string;
    static PKCS7Decoder(buff: Buffer): Buffer;
    static PKCS7Encoder(buff: Buffer): Buffer;
}
