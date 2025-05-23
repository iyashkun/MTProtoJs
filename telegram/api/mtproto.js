const crypto = require('crypto');
const net = require('net');
const { promisify } = require('util');

class MTProto {
    constructor(apiId, apiHash, dcId = 2) {
        this.apiId = apiId;
        this.apiHash = apiHash;
        this.dcId = dcId;
        this.authKey = null;
        this.serverSalt = null;
        this.sessionId = crypto.randomBytes(8);
        this.seqNo = 0;
        this.msgId = 0;
        this.socket = null;
        this.connected = false;
        this.pendingAcks = new Set();
        this.waitingForResponse = new Map();
    }

    getDcEndpoint(dcId) {
        const endpoints = {
            1: { ip: '149.154.175.50', port: 443 },
            2: { ip: '149.154.167.51', port: 443 },
            3: { ip: '149.154.175.100', port: 443 },
            4: { ip: '149.154.167.91', port: 443 },
            5: { ip: '149.154.171.5', port: 443 }
        };
        return endpoints[dcId] || endpoints[2];
    }

    generateMessageId() {
        const now = Date.now();
        this.msgId = Math.floor(now / 1000) * 4294967296 + (this.msgId % 4294967296) + 1;
        return this.msgId;
    }

    generateSeqNo(contentRelated = true) {
        const seqNo = this.seqNo * 2 + (contentRelated ? 1 : 0);
        this.seqNo++;
        return seqNo;
    }

    async connect() {
        const endpoint = this.getDcEndpoint(this.dcId);
        
        return new Promise((resolve, reject) => {
            this.socket = net.createConnection(endpoint.port, endpoint.ip);
            
            this.socket.on('connect', () => {
                this.connected = true;
                resolve();
            });
            
            this.socket.on('error', (err) => {
                reject(err);
            });
            
            this.socket.on('data', (data) => {
                this.handleResponse(data);
            });
        });
    }

    writeInt32(value, buffer, offset = 0) {
        buffer.writeInt32LE(value, offset);
        return offset + 4;
    }

    writeInt64(value, buffer, offset = 0) {
        const low = value & 0xffffffff;
        const high = Math.floor(value / 0x100000000);
        buffer.writeInt32LE(low, offset);
        buffer.writeInt32LE(high, offset + 4);
        return offset + 8;
    }

    writeBytes(data, buffer, offset = 0) {
        data.copy(buffer, offset);
        return offset + data.length;
    }

    writeString(str, buffer, offset = 0) {
        const strBuffer = Buffer.from(str, 'utf8');
        const len = strBuffer.length;
        
        if (len < 254) {
            buffer.writeUInt8(len, offset);
            offset += 1;
        } else {
            buffer.writeUInt8(254, offset);
            buffer.writeUInt8(len & 0xff, offset + 1);
            buffer.writeUInt8((len >> 8) & 0xff, offset + 2);
            buffer.writeUInt8((len >> 16) & 0xff, offset + 3);
            offset += 4;
        }
        
        strBuffer.copy(buffer, offset);
        offset += len;
        
        const padding = (4 - ((len + (len < 254 ? 1 : 4)) % 4)) % 4;
        buffer.fill(0, offset, offset + padding);
        return offset + padding;
    }

    readInt32(buffer, offset = 0) {
        return buffer.readInt32LE(offset);
    }

    readInt64(buffer, offset = 0) {
        const low = buffer.readInt32LE(offset);
        const high = buffer.readInt32LE(offset + 4);
        return high * 0x100000000 + (low >>> 0);
    }

    aesIgeEncrypt(data, key, iv) {
        const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16));
        cipher.setAutoPadding(false);
        
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return this.igeProcess(encrypted, key, iv, true);
    }

    aesIgeDecrypt(data, key, iv) {
        const decrypted = this.igeProcess(data, key, iv, false);
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
        decipher.setAutoPadding(false);
        
        return Buffer.concat([decipher.update(decrypted), decipher.final()]);
    }

    igeProcess(data, key, iv, encrypt) {
        const blockSize = 16;
        const result = Buffer.alloc(data.length);
        let iv1 = iv.slice(0, blockSize);
        let iv2 = iv.slice(blockSize, blockSize * 2);
        
        for (let i = 0; i < data.length; i += blockSize) {
            const block = data.slice(i, i + blockSize);
            let processedBlock;
            
            if (encrypt) {
                const xored = Buffer.alloc(blockSize);
                for (let j = 0; j < blockSize; j++) {
                    xored[j] = block[j] ^ iv1[j];
                }
                const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
                cipher.setAutoPadding(false);
                processedBlock = cipher.update(xored);
                
                for (let j = 0; j < blockSize; j++) {
                    processedBlock[j] ^= iv2[j];
                }
                
                iv1 = processedBlock;
                iv2 = block;
            } else {
                const xored = Buffer.alloc(blockSize);
                for (let j = 0; j < blockSize; j++) {
                    xored[j] = block[j] ^ iv2[j];
                }
                const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
                decipher.setAutoPadding(false);
                processedBlock = decipher.update(xored);
                
                for (let j = 0; j < blockSize; j++) {
                    processedBlock[j] ^= iv1[j];
                }
                
                iv1 = block;
                iv2 = processedBlock;
            }
            
            processedBlock.copy(result, i);
        }
        
        return result;
    }

    sha1(data) {
        return crypto.createHash('sha1').update(data).digest();
    }

    sha256(data) {
        return crypto.createHash('sha256').update(data).digest();
    }

    async sendPlainMessage(data) {
        const authKeyId = Buffer.alloc(8);
        const messageId = Buffer.alloc(8);
        this.writeInt64(this.generateMessageId(), messageId);
        const messageLength = Buffer.alloc(4);
        this.writeInt32(data.length, messageLength);
        
        const packet = Buffer.concat([authKeyId, messageId, messageLength, data]);
        
        return new Promise((resolve, reject) => {
            this.socket.write(packet, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    async sendEncryptedMessage(data) {
        if (!this.authKey) {
            throw new Error('Auth key not set');
        }
        
        const msgKey = this.sha256(Buffer.concat([
            this.authKey.slice(88, 120),
            data
        ])).slice(8, 24);
        
        const { aesKey, aesIv } = this.generateAesKeyIv(msgKey, true);
        const encryptedData = this.aesIgeEncrypt(data, aesKey, aesIv);
        
        const authKeyId = this.sha1(this.authKey).slice(-8);
        const packet = Buffer.concat([authKeyId, msgKey, encryptedData]);
        
        return new Promise((resolve, reject) => {
            this.socket.write(packet, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    generateAesKeyIv(msgKey, isFromServer = false) {
        const x = isFromServer ? 8 : 0;
        const sha256a = this.sha256(Buffer.concat([msgKey, this.authKey.slice(x, x + 36)]));
        const sha256b = this.sha256(Buffer.concat([this.authKey.slice(40 + x, 76 + x), msgKey]));
        
        const aesKey = Buffer.concat([sha256a.slice(0, 8), sha256b.slice(8, 24), sha256a.slice(24, 32)]);
        const aesIv = Buffer.concat([sha256b.slice(0, 8), sha256a.slice(8, 24), sha256b.slice(24, 32)]);
        
        return { aesKey, aesIv };
    }

    handleResponse(data) {
        if (data.length < 8) return;
        
        const authKeyId = data.slice(0, 8);
        
        if (authKeyId.equals(Buffer.alloc(8))) {
            this.handlePlainResponse(data);
        } else {
            this.handleEncryptedResponse(data);
        }
    }

    handlePlainResponse(data) {
        const messageId = this.readInt64(data, 8);
        const messageLength = this.readInt32(data, 16);
        const messageData = data.slice(20, 20 + messageLength);
        
        const constructor = this.readInt32(messageData, 0);
        
        if (this.waitingForResponse.has(messageId)) {
            const callback = this.waitingForResponse.get(messageId);
            this.waitingForResponse.delete(messageId);
            callback(null, messageData);
        }
    }

    handleEncryptedResponse(data) {
        if (!this.authKey) return;
        
        const msgKey = data.slice(8, 24);
        const encryptedData = data.slice(24);
        
        const { aesKey, aesIv } = this.generateAesKeyIv(msgKey, false);
        const decryptedData = this.aesIgeDecrypt(encryptedData, aesKey, aesIv);
        
        const serverSalt = this.readInt64(decryptedData, 0);
        const sessionId = decryptedData.slice(8, 16);
        const messageId = this.readInt64(decryptedData, 16);
        const seqNo = this.readInt32(decryptedData, 24);
        const messageLength = this.readInt32(decryptedData, 28);
        const messageData = decryptedData.slice(32, 32 + messageLength);
        
        if (this.waitingForResponse.has(messageId)) {
            const callback = this.waitingForResponse.get(messageId);
            this.waitingForResponse.delete(messageId);
            callback(null, messageData);
        }
    }

    async reqPQ() {
        const nonce = crypto.randomBytes(16);
        const reqPqData = Buffer.alloc(20);
        let offset = 0;
        
        offset = this.writeInt32(0x60469778, reqPqData, offset);
        offset = this.writeBytes(nonce, reqPqData, offset);
        
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve({ nonce, data });
            });
            
            this.sendPlainMessage(reqPqData).catch(reject);
        });
    }

    async reqDHParams(nonce, serverNonce, p, q, publicKeyFingerprint, encryptedData) {
        const reqDhParamsData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0xd712e4be, reqDhParamsData, offset);
        offset = this.writeBytes(nonce, reqDhParamsData, offset);
        offset = this.writeBytes(serverNonce, reqDhParamsData, offset);
        offset = this.writeBytes(p, reqDhParamsData, offset);
        offset = this.writeBytes(q, reqDhParamsData, offset);
        offset = this.writeInt64(publicKeyFingerprint, reqDhParamsData, offset);
        offset = this.writeString(encryptedData.toString('base64'), reqDhParamsData, offset);
        
        const finalData = reqDhParamsData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendPlainMessage(finalData).catch(reject);
        });
    }

    async setClientDHParams(nonce, serverNonce, encryptedData) {
        const setClientDhParamsData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0xf5045f1f, setClientDhParamsData, offset);
        offset = this.writeBytes(nonce, setClientDhParamsData, offset);
        offset = this.writeBytes(serverNonce, setClientDhParamsData, offset);
        offset = this.writeString(encryptedData.toString('base64'), setClientDhParamsData, offset);
        
        const finalData = setClientDhParamsData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendPlainMessage(finalData).catch(reject);
        });
    }

    async authSendCode(phoneNumber) {
        const authSendCodeData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0xa677244f, authSendCodeData, offset);
        offset = this.writeString(phoneNumber, authSendCodeData, offset);
        offset = this.writeInt32(this.apiId, authSendCodeData, offset);
        offset = this.writeString(this.apiHash, authSendCodeData, offset);
        
        const finalData = authSendCodeData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendEncryptedMessage(finalData).catch(reject);
        });
    }

    async authSignIn(phoneNumber, phoneCodeHash, phoneCode) {
        const authSignInData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0xbcd51581, authSignInData, offset);
        offset = this.writeString(phoneNumber, authSignInData, offset);
        offset = this.writeString(phoneCodeHash, authSignInData, offset);
        offset = this.writeString(phoneCode, authSignInData, offset);
        
        const finalData = authSignInData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendEncryptedMessage(finalData).catch(reject);
        });
    }

    async getUsersSelf() {
        const getUsersSelfData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0xb98886cf, getUsersSelfData, offset);
        offset = this.writeInt32(0x1cb5c415, getUsersSelfData, offset);
        offset = this.writeInt32(1, getUsersSelfData, offset);
        offset = this.writeInt32(0x73f1f8dc, getUsersSelfData, offset);
        
        const finalData = getUsersSelfData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendEncryptedMessage(finalData).catch(reject);
        });
    }

    async sendMessage(peerId, message) {
        const sendMessageData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0xfa88427a, sendMessageData, offset);
        offset = this.writeInt32(0, sendMessageData, offset);
        offset = this.writeInt32(0x9ba2d800, sendMessageData, offset);
        offset = this.writeInt64(peerId, sendMessageData, offset);
        offset = this.writeInt64(crypto.randomBytes(8).readBigInt64LE(), sendMessageData, offset);
        offset = this.writeString(message, sendMessageData, offset);
        
        const finalData = sendMessageData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendEncryptedMessage(finalData).catch(reject);
        });
    }

    async getDialogs(offsetDate = 0, offsetId = 0, offsetPeer = null, limit = 100) {
        const getDialogsData = Buffer.alloc(1024);
        let offset = 0;
        
        offset = this.writeInt32(0x191ba9c5, getDialogsData, offset);
        offset = this.writeInt32(0, getDialogsData, offset);
        offset = this.writeInt32(offsetDate, getDialogsData, offset);
        offset = this.writeInt32(offsetId, getDialogsData, offset);
        if (offsetPeer) {
            offset = this.writeInt32(0x9023bc9f, getDialogsData, offset);
        } else {
            offset = this.writeInt32(0x56e6390e, getDialogsData, offset);
        }
        offset = this.writeInt32(limit, getDialogsData, offset);
        offset = this.writeInt32(0, getDialogsData, offset);
        
        const finalData = getDialogsData.slice(0, offset);
        const messageId = this.generateMessageId();
        
        return new Promise((resolve, reject) => {
            this.waitingForResponse.set(messageId, (err, data) => {
                if (err) reject(err);
                else resolve(data);
            });
            
            this.sendEncryptedMessage(finalData).catch(reject);
        });
    }

    disconnect() {
        if (this.socket) {
            this.socket.destroy();
            this.connected = false;
        }
    }
}

module.exports = MTProto;
