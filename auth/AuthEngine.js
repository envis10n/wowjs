const crypto = require('crypto');
const buffertrim = require('buffertrim');
const bigi = require('bigi');

function SHAInterleave(input){
    var hash = crypto.createHash('sha1').update(input).digest();
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
    e = crypto.createHash('sha1').update(e).digest();
    f = crypto.createHash('sha1').update(f).digest();
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

class AuthEngine {
    constructor(){
        const self = this;
        this.g = Buffer.from([7]);
        this.N = Buffer.from('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 'hex');
        this.Nb = bigi.fromHex('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7');
        this.Salt = Buffer.from([173, 208, 58, 49, 210, 113, 20, 70, 117, 242, 112, 126, 80, 38, 182, 210, 241, 134, 89, 153, 118, 2, 80, 170, 185, 69, 224, 158, 221, 42, 163, 69]);
        this.k = Buffer.from([3]);
        this.b = crypto.randomBytes(20);
        this.CrcSalt = crypto.randomBytes(16);
    };
    CalculateB(username, pwHash, cb){
        const self = this;
        self.username = username;
        self.x = bigi.fromHex(crypto.createHash('sha1').update(self.Salt).update(pwHash).digest('hex'));
        var g = bigi.fromBuffer(self.g);
        var k = bigi.fromBuffer(self.k);
        var N = self.Nb;
        self.v = g.modPow(self.x, N);
        var b = bigi.fromBuffer(self.b);
        self.Bn = k.multiply(self.v).add(b).mod(N);
        self.B = self.Bn.toBuffer();
    };
    CalculateM1(A){
        const self = this;
        var g = bigi.fromBuffer(self.g);
        var k = bigi.fromBuffer(self.k);
        var N = self.Nb;
        var b = bigi.fromBuffer(self.b);
        self.A = A;
        self.An = bigi.fromBuffer(self.A);
        self.u = bigi.fromHex(crypto.createHash('sha1').update(self.A).update(self.B).digest('hex'));
        self.S = self.An.multiply(self.v.modPow(self.u, N)).modPow(b, N).toBuffer();
        var Hn = crypto.createHash('sha1').update(self.N).digest();
        var Hg = crypto.createHash('sha1').update(self.g).digest();
        self.K = SHAInterleave(self.S);
        var Hor = bigi.fromBuffer(Hn).xor(bigi.fromBuffer(Hg)).toBuffer();
        var Hi = crypto.createHash('sha1').update(self.username).digest();
        self.M1 = crypto.createHash('sha1').update(Hor).update(Hi).update(self.Salt).update(self.A).update(self.B).update(self.K).digest();
    }
}

module.exports = AuthEngine;