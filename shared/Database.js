const MongoClient = require('mongodb').MongoClient;
const EventHandler = require('events');

var events = new EventHandler();

MongoClient.connect('mongodb://localhost:27017/', function(err, client){
    if(err) throw err;
    events.db = client.db('wowjs');
    events.emit('ready');
});

module.exports = events;