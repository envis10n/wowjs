const crypto = require('crypto');
const buffertrim = require('buffertrim');
const bn = require('bignum');

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

    for(var i = 0;i<hash.length/2;i++)
    {
        e[i] = hash[i * 2];
        f[i] = hash[i * 2 + 1];
    }
    eh = Buffer.alloc(20);
    sha1(e).copy(eh, 0, 0, 20);
    fh = Buffer.alloc(20);
    sha1(f).copy(fh, 0, 0, 20);
    var fin = Buffer.alloc(40);
    for(var i = 0;i<20;i++)
    {
        fin[i * 2] = eh[i];
        fin[i * 2 + 1] = fh[i];
    }
    return fin.reverse();
}

function scrambler(aa, ba){
    var A = bn.fromBuffer(aa);
    var B = bn.fromBuffer(ba);
    return bn.fromBuffer(sha1(toBuffer(A, 32).reverse(), B.toBuffer().reverse()).reverse());
}

function toBuffer(bign, length){
    if(!bign instanceof bn){
        throw new Error('Type Error: Input not bignum.');
    }
    else
    {
        return length ? bign.toBuffer({size: length}) : bign.toBuffer();
    }
}

const s = bn.fromBuffer(crypto.pseudoRandomBytes(32));

const N = new bn('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

const g = new bn(7);

const b = bn.fromBuffer(crypto.pseudoRandomBytes(19));

class AuthEngine {
    constructor(){
        this.Salt = bn.toBuffer(s, {size: 32}).reverse();
        this.N = bn.toBuffer(N, {size: 32}).reverse();
        this.CrcSalt = bn.fromBuffer(crypto.randomBytes(16)).toBuffer({size: 16});
    };
    generate_v(I, pw){
        this.I = I;
        var p = new bn(pw, 16);
        var h = sha1(bn.toBuffer(s).reverse(), bn.toBuffer(p));
        h.reverse();
        this.v = bn.powm(g, bn.fromBuffer(h), N);
        this.generate_B();
    }
    generate_B(){
        const self = this;
        this.B = bn.add(bn.mul(self.v, 3), bn.powm(g, b, N)).mod(N);
        this.Bn = this.B.toBuffer();
        this.PublicB = this.B.toBuffer({size: 32}).reverse();
        this.g = g.toBuffer({size: 1});
    }
    generate_K(A){
        const self = this;
        this.u = scrambler(A, self.Bn);
        this.A = A;
        this.S = bn.powm(bn.mul(bn.fromBuffer(A), bn.powm(self.v, self.u, N)), b, N);
        this.K = bn.fromBuffer(SHAInterleave(self.S.toBuffer({size: 32}).reverse()));
    }
    generate_M(){
        const self = this;
        var Hn = Buffer.alloc(20);
        sha1(bn.toBuffer(N).reverse()).reverse().copy(Hn, 0, 0, 20);
        var Hg = Buffer.alloc(20);
        sha1(bn.toBuffer(g)).reverse().copy(Hg, 0, 0, 20);

        var t = Buffer.alloc(20);

        for(var i = 0;i<20;i++)
        {
            t[i] = Hn[i] ^ Hg[i];
        }

        var Ih = Buffer.alloc(20);
        sha1(self.I).reverse().copy(Ih, 0, 0, 20);

        this.M1 = sha1(t.reverse(), Ih.reverse(), bn.toBuffer(s).reverse(), self.A.reverse(), self.B.toBuffer().reverse(), self.K.toBuffer().reverse()).reverse();
    }
}

module.exports = AuthEngine;