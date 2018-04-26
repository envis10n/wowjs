const Enum = require('../shared/Enums');
const AuthCMD = Enum.AuthCMD;
const AccountState = Enum.AccountState;
const AuthResult = Enum.AuthResult;
const LoginResponse = Enum.LoginResponse;

var RS = require('./RSHandler');

const net = require('net');
const {format} = require('util');
const authserver = net.createServer((c)=>{
    c.on('data', function(data){
        switch(data[0]){
            case AuthCMD.CMD_AUTH_LOGON_CHALLENGE:
                RS.LogonChallenge(data, c);
            break;
            case AuthCMD.CMD_AUTH_LOGON_PROOF:
                RS.LogonProof(data, c);
            break;
            default:
                c.write(Buffer.from([AuthCMD.CMD_AUTH_LOGON_PROOF, AccountState.LOGIN_FAILED]));
            break;
        }
    });
});

authserver.listen(3724, ()=>{
    console.log('Auth server listening...');
});