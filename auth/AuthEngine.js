const crypto = require('crypto');
const buffertrim = require('buffertrim');
const bigi = require('bigi');

function sha1(...input){
    var hash = crypto.createHash('sha1');
    input.forEach(function(inp){
        hash.update(inp);
    });
    return hash.digest();
}

function SHAInterleave(input){
    var hash = sha1(input);
    hash = buffertrim.trimStart(hash);
    if(hash.length % 2 != 0)
    {
        hash = hash.slice(1);
    }
    var e = Buffer.alloc(hash.length / 2);
    var f = Buffer.alloc(hash.length / 2);

    var et = 0;
    var ft = 0;

    for(var i = 0;i<hash.length;i++)
    {
        if(i % 2 == 0)
        {
            e[et] = hash[i];
            et++;
        }
        else
        {
            f[ft] = hash[i];
            ft++;
        }
    }
    e = sha1(e);
    f = sha1(f);
    var fin = Buffer.alloc(hash.length * 2);
    var fit = 0;
    for(var i = 0;i<e.length;i+=2)
    {
        fin[i] = e[fit];
        fin[i+1] = f[fit];
        fit++;
    }
    return fin;
}

function scrambler(a, b, pad){
    var A = Buffer.alloc(pad);
    var B = Buffer.alloc(pad);
    a.reverse();
    b.reverse();
    a.copy(A, 0);
    b.copy(B, 0);
    A.reverse();
    B.reverse();
    return sha1(A, B);
}

class AuthEngine {
    constructor(){
        const self = this;
        this.g = Buffer.from([7]);
        this._bNg = Buffer.from([7]);
        this._bNg.reverse();
        this._bNg = bigi.fromBuffer(self._bNg);
        this.N = Buffer.from([137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191, 191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183]);
        this._bNn = Buffer.from([137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191, 191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183]);
        this._bNn.reverse();
        this._bNn = bigi.fromBuffer(self._bNn);
        this.Salt = Buffer.from([173, 208, 58, 49, 210, 113, 20, 70, 117, 242, 112, 126, 80, 38, 182, 210, 241, 134, 89, 153, 118, 2, 80, 170, 185, 69, 224, 158, 221, 42, 163, 69]);
        this.k = Buffer.from([3]);
        this._bNk = Buffer.from([3]);
        this._bNk.reverse();
        this._bNk = bigi.fromBuffer(self._bNk);
        this.b = crypto.randomBytes(20);
        this.CrcSalt = crypto.randomBytes(16);
    };
    CalculateB(){
        const self = this;
        self.b.reverse();
        self._bNb = bigi.fromBuffer(self.b);
        self.b.reverse();
        var ptr1 = self._bNg.modPow(self._bNb, self._bNn);
        var ptr2 = self._bNk.multiply(self._bNv);
        var ptr3 = ptr1.add(ptr2);
        self._bnPublicB = ptr3.mod(self._bNn);
        self.PublicB = self._bnPublicB.toBuffer();
        self.PublicB.reverse();
    };
    CalculateK(){
        const self = this;
        console.log('S: ',self.S);
        self.K = SHAInterleave(self.S);
    };
    CalculateS(){
        const self = this;
        var ptr1 = self._bNv.modPow(self._bnu, self._bNn);
        var ptr2 = self._bna.multiply(ptr1);
        self._bns = ptr2.modPow(self._bNb, self._bNn);
        self.S = self._bns.toBuffer();
        self.S.reverse();
        self.CalculateK();
    };
    CalculateU(a){
        const self = this;
        self._a = a;
        self.U = scrambler(a, self.PublicB, self.N.length);
        self.U.reverse();
        self._bnu = bigi.fromBuffer(self.U);
        self.U.reverse();
        a.reverse();
        self._bna = bigi.fromBuffer(a);
        a.reverse();
        self.CalculateS();
    };
    CalculateV(){
        const self = this;
        self._bNv = self._bNg.modPow(self._bNx, self._bNn);
        self.CalculateB();
    }
    CalculateX(username, pwHash){
        const self = this;
        self._username = username;
        var buffer3 = sha1(self.Salt, pwHash);
        buffer3.reverse();
        self._bNx = bigi.fromBuffer(buffer3);
        self.CalculateV();
    };
    CalculateM1(){
        const self = this;
        var userhash = sha1(self._username);
        var nHash = sha1(self.N);
        var gHash = sha1(self.g);
        for(var i = 0;i<nHash.length;i++)
        {
            nHash[i] ^= gHash[i];
        }
        self.M1 = sha1(Buffer.concat([nHash, userhash, self.Salt, self._a, self.PublicB, self.K]));
    }
}

module.exports = AuthEngine;