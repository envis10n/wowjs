var db = require('./shared/Database');

db.on('ready', ()=>{
    require('./auth/index');
});