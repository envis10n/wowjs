const Enum = require('../shared/Enums');
const AuthCMD = Enum.AuthCMD;
const AccountState = Enum.AccountState;
const AuthResult = Enum.AuthResult;
const LoginResponse = Enum.LoginResponse;
var sLog = require('../shared/sLog');
var db = require('../shared/Database');
const AuthEngine = require('./AuthEngine');

const versions = [5875,6005,6141];

// Test user :/
var test = {
    id: 0,
    sha_pass_hash: '3d0d99423e31fcc67a6745ec89d70d700344bc76',
    gmlevel: 0,
    expansion: 0
}

module.exports.LogonChallenge = function(data, client){
    var iUpper = data[33] - 1;
    var packetAccount = '';
    var packetIp = '';
    var accState;
    for(i = 0;i<=iUpper;i++)
    {
        packetAccount += String.fromCodePoint(data[34+i]);
    }
    packetIp = data[29].toString()+'.'+data[30].toString()+'.'+data[31].toString()+'.'+data[32].toString();
    var bMajor = data[8];
    var bMinor = data[9];
    var bRevision = data[10];
    var clientBuild = Buffer.from([data[11], data[12]]).readInt16LE(0);
    var clientLanguage = String.fromCodePoint(data[24])+String.fromCodePoint(data[23])+String.fromCodePoint(data[22])+String.fromCodePoint(data[21]);
    sLog.debug('[%s] [%s:%d] CMD_AUTH_LOGON_CHALLENGE [%s] [%s] [%d.%d.%d.%d] [%s]', new Date().toTimeString().split(' ').shift(), client.address().address, client.address().port, packetAccount, packetIp, bMajor, bMinor, bRevision, clientBuild, clientLanguage);
    if(bMajor == 0 && bMinor == 0 && bRevision == 0 || !versions.find((build)=>{
        return build == clientBuild;
    }))
        client.write(Buffer.from([AuthCMD.CMD_AUTH_LOGON_PROOF, AccountState.LOGIN_BADVERSION]));
    else
    {
        db.db.collection('accounts').find({username: packetAccount}).toArray(function(err, accounts){
            if(err)
            {
                client.write(Buffer.from([AuthCMD.CMD_AUTH_LOGON_PROOF, AccountState.LOGIN_DBBUSY]));
                sLog.error(err);
            }
            if(!accounts)
            {
                client.write(Buffer.from([AuthCMD.CMD_AUTH_LOGON_PROOF, AccountState.LOGIN_DBBUSY]));
                sLog.error('Accounts array empty.');
            }
            if(accounts.length > 0)
            {
                accState = AccountState.LOGIN_OK;
                var accountd = accounts[0];
                var account = packetAccount;
                var pwHash = accountd.sha_pass_hash;
                client.Access = accountd.gmlevel;
                client.AuthEngine = new AuthEngine();
                client.AuthEngine.CalculateX(accountd.username, pwHash);
                var header = Buffer.from([AuthCMD.CMD_AUTH_LOGON_CHALLENGE, AccountState.LOGIN_OK, 0]);
                var control = Buffer.from([1,7,32]);
                var dataResponse = Buffer.concat([header, client.AuthEngine.PublicB, control, client.AuthEngine.N, client.AuthEngine.Salt, client.AuthEngine.CrcSalt, Buffer.from([0])]);
                sLog.debug('User exists. Responding...');
                sLog.debug('Response: '+dataResponse.length);
                client.write(dataResponse);
            }
            else
            {
                sLog.debug('User does not exist.');
                client.write(Buffer.from([AuthCMD.CMD_AUTH_LOGON_PROOF, AccountState.LOGIN_UNKNOWN_ACCOUNT]));
            }
        });
    }
};

module.exports.LogonProof = function(data, client){
    sLog.debug('[%s] [%s:%d] CMD_AUTH_LOGON_PROOF', new Date().toTimeString().split(' ').shift(), client.address().address, client.address().port);
    var a = Buffer.alloc(32);
    data.copy(a, 0, 1, 33);
    var m1 = Buffer.alloc(20);
    data.copy(m1, 0, 33, 53);
    client.AuthEngine.CalculateU(a);
    client.AuthEngine.CalculateM1();
    var passCheck = true;

    console.log('Server M1: '+client.AuthEngine.M1.toString('base64'));
    console.log('Client M1: '+m1.toString('base64'));

    for(var i = 0;i<20;i++)
    {
        if(m1[i] != client.AuthEngine.M1[i])
        {
            passCheck = false;
            break;
        }
    }

    if(passCheck)
    {
        sLog.info('Client login success.');
    }
    else
    {
        sLog.error('Client bad login.');
        var dataResponse = Buffer.alloc(2);
        dataResponse[0] = AuthCMD.CMD_AUTH_LOGON_PROOF;
        dataResponse[1] = AccountState.LOGIN_UNKNOWN_ACCOUNT;
        client.write(dataResponse);
    }
};