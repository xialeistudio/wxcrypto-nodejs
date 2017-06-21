"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var XMLParser = require("xml2js");
var buildXML = new XMLParser.Builder({
    rootName: 'xml',
    cdata: true,
    headless: true,
    renderOpts: { indent: ' ', pretty: true },
});
var WxCrypto = (function () {
    /**
     * 构造方法
     * @param token
     * @param appid
     * @param encodingAESKey
     */
    function WxCrypto(token, appid, encodingAESKey) {
        this.token = token;
        this.appid = appid;
        this.aesKey = new Buffer(encodingAESKey + "=", 'base64');
        this.iv = this.aesKey.slice(0, 16);
    }
    /**
     * xml转换为json
     * @param xml
     * @returns {Promise}
     */
    WxCrypto.xml2json = function (xml) {
        return new Promise(function (resolve, reject) {
            XMLParser.parseString(xml, {
                rootName: 'xml',
                cdata: true,
                headless: true,
                renderOpts: { indent: ' ', pretty: true },
            }, function (e, data) {
                if (e) {
                    return reject(e);
                }
                var result = {};
                Object.keys(data.xml).forEach(function (key) {
                    result[key] = data.xml[key][0];
                });
                resolve(result);
            });
        });
    };
    /**
     * 消息解密
     * @param msgSignature
     * @param timestamp
     * @param nonce
     * @param xml
     * @returns {Promise}
     */
    WxCrypto.prototype.decryptMsg = function (msgSignature, timestamp, nonce, xml) {
        return __awaiter(this, void 0, void 0, function () {
            var data, msgEncrypt, decryptedMessage;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, WxCrypto.xml2json(xml)];
                    case 1:
                        data = _a.sent();
                        msgEncrypt = data.Encrypt;
                        if (this.getSignature(timestamp, nonce, msgEncrypt) !== msgSignature) {
                            throw new Error('msgSignature is not invalid');
                        }
                        decryptedMessage = this.decrypt(msgEncrypt);
                        return [2 /*return*/, new Promise(function (resolve, reject) {
                                XMLParser.parseString(decryptedMessage, { explicitArray: false }, function (e, result) { return e ? reject(e) : resolve(result.xml); });
                            })];
                }
            });
        });
    };
    /**
     * 消息加密
     * @param replyMsg
     * @param opts
     * @returns {string}
     */
    WxCrypto.prototype.encryptMsg = function (replyMsg, opts) {
        var result = {};
        var options = opts || {};
        result.Encrypt = this.encrypt(replyMsg);
        result.Nonce = options.nonce || parseInt((Math.random() * 100000000000).toString(), 10);
        result.TimeStamp = options.timestamp || new Date().getTime();
        result.MsgSignature = this.getSignature(result.TimeStamp, result.Nonce, result.Encrypt);
        return buildXML.buildObject(result);
    };
    WxCrypto.prototype.encrypt = function (xmlMsg) {
        var random16 = new Buffer(parseInt((Math.random() * 100000000000).toString(), 10));
        var msg = new Buffer(xmlMsg);
        var msgLength = new Buffer(4);
        msgLength.writeUInt32BE(msg.length, 0);
        var corpId = new Buffer(this.appid);
        var rawMsg = Buffer.concat([random16, msgLength, msg, corpId]);
        var cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, this.iv);
        var cipheredMsg = Buffer.concat([cipher.update(rawMsg), cipher.final()]);
        return cipheredMsg.toString('base64');
    };
    WxCrypto.prototype.decrypt = function (str) {
        var aesCipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, this.iv);
        aesCipher.setAutoPadding(false);
        var decipheredBuff = Buffer.concat([aesCipher.update(str, 'base64'), aesCipher.final()]);
        decipheredBuff = WxCrypto.PKCS7Decoder(decipheredBuff);
        var lenNetOrderCorpid = decipheredBuff.slice(16);
        var msgLen = lenNetOrderCorpid.slice(0, 4).readUInt32BE(0);
        var result = lenNetOrderCorpid.slice(4, msgLen + 4).toString();
        var appId = lenNetOrderCorpid.slice(msgLen + 4).toString();
        if (appId !== this.appid) {
            throw new Error('appId is invalid');
        }
        return result;
    };
    WxCrypto.prototype.getSignature = function (timestamp, nonce, encrypt) {
        var signature = [this.token, timestamp, nonce, encrypt].sort().join('');
        var sha1 = crypto.createHash('sha1');
        sha1.update(signature);
        return sha1.digest('hex');
    };
    WxCrypto.PKCS7Decoder = function (buff) {
        var pad = buff[buff.length - 1];
        if (pad < 1 || pad > 32) {
            pad = 0;
        }
        return buff.slice(0, buff.length - pad);
    };
    WxCrypto.PKCS7Encoder = function (buff) {
        var blockSize = 32;
        var strSize = buff.length;
        var amountToPad = blockSize - (strSize % blockSize);
        var pad = new Buffer(amountToPad - 1);
        pad.fill(String.fromCharCode(amountToPad));
        return Buffer.concat([buff, pad]);
    };
    return WxCrypto;
}());
exports.default = WxCrypto;
//# sourceMappingURL=index.js.map