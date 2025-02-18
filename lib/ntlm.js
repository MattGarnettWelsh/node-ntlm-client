"use strict";

const os = require("os"),
    flags = require("./flags"),
    hash = require("./hash");

const NTLMSIGNATURE = "NTLMSSP\0";

function createType1Message(workstation, target) {
    let dataPos = 32,
        pos = 0,
        buf = new Buffer(1024);

    workstation = workstation === undefined ? os.hostname() : workstation;
    target = target === undefined ? "" : target;

    //signature
    buf.write(NTLMSIGNATURE, pos, NTLMSIGNATURE.length, "ascii");
    pos += NTLMSIGNATURE.length;

    //message type
    buf.writeUInt32LE(1, pos);
    pos += 4;

    //flags
    buf.writeUInt32LE(
        flags.NTLMFLAG_NEGOTIATE_OEM |
            flags.NTLMFLAG_REQUEST_TARGET |
            flags.NTLMFLAG_NEGOTIATE_NTLM_KEY |
            flags.NTLMFLAG_NEGOTIATE_NTLM2_KEY |
            flags.NTLMFLAG_NEGOTIATE_ALWAYS_SIGN,
        pos
    );
    pos += 4;

    //domain security buffer
    buf.writeUInt16LE(target.length, pos);
    pos += 2;
    buf.writeUInt16LE(target.length, pos);
    pos += 2;
    buf.writeUInt32LE(target.length === 0 ? 0 : dataPos, pos);
    pos += 4;

    if (target.length > 0) {
        dataPos += buf.write(target, dataPos, "ascii");
    }

    //workstation security buffer
    buf.writeUInt16LE(workstation.length, pos);
    pos += 2;
    buf.writeUInt16LE(workstation.length, pos);
    pos += 2;
    buf.writeUInt32LE(workstation.length === 0 ? 0 : dataPos, pos);
    pos += 4;

    if (workstation.length > 0) {
        dataPos += buf.write(workstation, dataPos, "ascii");
    }

    return "NTLM " + buf.toString("base64", 0, dataPos);
}

function decodeType2Message(input) {
    if (input === undefined) {
        throw new Error("Invalid argument: input is undefined");
    }

    // Ensure we have a string; if not, try extracting from a headers object.
    if (typeof input !== "string") {
        if (input && input.headers && input.headers["www-authenticate"]) {
            input = input.headers["www-authenticate"];
        } else {
            throw new Error("Invalid argument: Unable to extract string from input");
        }
    }

    // Extract the NTLM portion from the header if present.
    let ntlmMatch = /^NTLM ([^,\s]+)/.exec(input);
    if (ntlmMatch) {
        input = ntlmMatch[1];
    }

    // Use Buffer.from instead of new Buffer for newer Node versions.
    let buf = Buffer.from(input, "base64");

    // Check for valid NTLM signature.
    const signature = buf.toString("ascii", 0, NTLMSIGNATURE.length);
    if (signature !== NTLMSIGNATURE) {
        throw new Error("Invalid message signature");
    }

    // Check for message type.
    const messageType = buf.readUInt32LE(NTLMSIGNATURE.length);
    if (messageType !== 2) {
        throw new Error("Invalid message type (expected type 2)");
    }

    let obj = {};
    // Read flags.
    obj.flags = buf.readUInt32LE(20);

    // Set encoding based on flags.
    obj.encoding = obj.flags & flags.NTLMFLAG_NEGOTIATE_OEM ? "ascii" : "ucs2";
    // Determine NTLM version.
    obj.version = obj.flags & flags.NTLMFLAG_NEGOTIATE_NTLM2_KEY ? 2 : 1;

    // Read challenge.
    obj.challenge = buf.slice(24, 32);

    // Read target name.
    obj.targetName = (function () {
        let length = buf.readUInt16LE(12);
        let offset = buf.readUInt32LE(16);
        if (length === 0) {
            return "";
        }
        if (offset + length > buf.length || offset < 32) {
            throw new Error("Bad type 2 message: target name data out of bounds");
        }
        return buf.toString(obj.encoding, offset, offset + length);
    })();

    // Read target info if the flag is set.
    if (obj.flags & flags.NTLMFLAG_NEGOTIATE_TARGET_INFO) {
        obj.targetInfo = (function () {
            let info = {};

            let length = buf.readUInt16LE(40);
            let offset = buf.readUInt32LE(44);

            // Create a buffer for the target info.
            let targetInfoBuffer = Buffer.alloc(length);
            buf.copy(targetInfoBuffer, 0, offset, offset + length);

            if (length === 0) {
                return info;
            }

            if (offset + length > buf.length || offset < 32) {
                throw new Error("Bad type 2 message: target info data out of bounds");
            }

            let pos = offset;
            while (pos < offset + length) {
                let blockType = buf.readUInt16LE(pos);
                pos += 2;
                let blockLength = buf.readUInt16LE(pos);
                pos += 2;

                if (blockType === 0) {
                    // Terminator block.
                    break;
                }

                let blockTypeStr;
                switch (blockType) {
                    case 1:
                        blockTypeStr = "SERVER";
                        break;
                    case 2:
                        blockTypeStr = "DOMAIN";
                        break;
                    case 3:
                        blockTypeStr = "FQDN";
                        break;
                    case 4:
                        blockTypeStr = "DNS";
                        break;
                    case 5:
                        blockTypeStr = "PARENT_DNS";
                        break;
                    default:
                        blockTypeStr = "UNKNOWN";
                        break;
                }

                if (blockTypeStr) {
                    const value = buf.toString("ucs2", pos, pos + blockLength);
                    info[blockTypeStr] = value;
                }

                pos += blockLength;
            }

            return {
                parsed: info,
                buffer: targetInfoBuffer,
            };
        })();
    }

    return obj;
}

function createType3Message(type2Message, username, password, workstation, target) {
    let dataPos = 52,
        buf = new Buffer(1024);

    if (workstation === undefined) {
        workstation = os.hostname();
    }

    if (target === undefined) {
        target = type2Message.targetName;
    }

    //signature
    buf.write(NTLMSIGNATURE, 0, NTLMSIGNATURE.length, "ascii");

    //message type
    buf.writeUInt32LE(3, 8);

    if (type2Message.version === 2) {
        dataPos = 64;

        let ntlmHash = hash.createNTLMHash(password),
            nonce = hash.createPseudoRandomValue(16),
            lmv2 = hash.createLMv2Response(type2Message, username, ntlmHash, nonce),
            ntlmv2 = hash.createNTLMv2Response(type2Message, username, ntlmHash, nonce);

        //lmv2 security buffer
        buf.writeUInt16LE(lmv2.length, 12);
        buf.writeUInt16LE(lmv2.length, 14);
        buf.writeUInt32LE(dataPos, 16);

        lmv2.copy(buf, dataPos);
        dataPos += lmv2.length;

        //ntlmv2 security buffer
        buf.writeUInt16LE(ntlmv2.length, 20);
        buf.writeUInt16LE(ntlmv2.length, 22);
        buf.writeUInt32LE(dataPos, 24);

        ntlmv2.copy(buf, dataPos);
        dataPos += ntlmv2.length;
    } else {
        let lmHash = hash.createLMHash(password),
            ntlmHash = hash.createNTLMHash(password),
            lm = hash.createLMResponse(type2Message.challenge, lmHash),
            ntlm = hash.createNTLMResponse(type2Message.challenge, ntlmHash);

        //lm security buffer
        buf.writeUInt16LE(lm.length, 12);
        buf.writeUInt16LE(lm.length, 14);
        buf.writeUInt32LE(dataPos, 16);

        lm.copy(buf, dataPos);
        dataPos += lm.length;

        //ntlm security buffer
        buf.writeUInt16LE(ntlm.length, 20);
        buf.writeUInt16LE(ntlm.length, 22);
        buf.writeUInt32LE(dataPos, 24);

        ntlm.copy(buf, dataPos);
        dataPos += ntlm.length;
    }

    //target name security buffer
    buf.writeUInt16LE(type2Message.encoding === "ascii" ? target.length : target.length * 2, 28);
    buf.writeUInt16LE(type2Message.encoding === "ascii" ? target.length : target.length * 2, 30);
    buf.writeUInt32LE(dataPos, 32);

    dataPos += buf.write(target, dataPos, type2Message.encoding);

    //user name security buffer
    buf.writeUInt16LE(type2Message.encoding === "ascii" ? username.length : username.length * 2, 36);
    buf.writeUInt16LE(type2Message.encoding === "ascii" ? username.length : username.length * 2, 38);
    buf.writeUInt32LE(dataPos, 40);

    dataPos += buf.write(username, dataPos, type2Message.encoding);

    //workstation name security buffer
    buf.writeUInt16LE(type2Message.encoding === "ascii" ? workstation.length : workstation.length * 2, 44);
    buf.writeUInt16LE(type2Message.encoding === "ascii" ? workstation.length : workstation.length * 2, 46);
    buf.writeUInt32LE(dataPos, 48);

    dataPos += buf.write(workstation, dataPos, type2Message.encoding);

    if (type2Message.version === 2) {
        //session key security buffer
        buf.writeUInt16LE(0, 52);
        buf.writeUInt16LE(0, 54);
        buf.writeUInt32LE(0, 56);

        //flags
        buf.writeUInt32LE(type2Message.flags, 60);
    }

    return "NTLM " + buf.toString("base64", 0, dataPos);
}

module.exports = {
    createType1Message,
    decodeType2Message,
    createType3Message,
};
