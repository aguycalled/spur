const Client = require('bitcoin-core');
const http = require('http');
const https = require('https');
const querystring = require('querystring');
const sqlite = require('sqlite3').verbose();
const fs = require("fs");
const async = require('async');
const crypto = require('ursa');
const timestamp = require('unix-timestamp');

const config = require('./config.json');

const file = "spur.db";
const exists = fs.existsSync(file);

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

var db = new sqlite.Database(file);

var txFee = 0.02;
var min_amount = 10;
var number_confirmations = 3;

var ready = 0;
var anon = 0;

const incoming_host = '176.9.19.245';
const incoming_port = '3000';

navClient = new Client({
  username: "aDU89DJQDHJ1Iodjwakjd",
  password: "d8u2j39quidhenwf98QJ",
  port: 44444,
  host: "127.0.0.1",
})

db.serialize(() =>
{

  if(!exists)
  {

    db.run("CREATE TABLE spur (date INT, src CHAR, dest CHAR, value FLOAT,amount FLOAT, fee FLOAT, flag1 FLOAT, flag2 INT, flag3 INT, flag4 CHAR, flag5 CHAR, flag6 CHAR)");

  }

});

if(anon == 1)
{

  check();

}
else
{

  ready = 1;
  mainLoop();

}

function check()
{
  var post_data = "num_addresses=0"

  var post_options = {
      host: incoming_host,
      port: incoming_port,
      path: '/api/check-node',
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(post_data)
      }
  };

  var post_req = https.request(post_options,(res) =>
    {

    res.setEncoding('utf8');
    res.on('data', (chunk) =>
    {

      var json = JSON.parse(chunk);

      if(json.status == 200 && json.type == "SUCCESS")
      {

        txFee = json.data.transaction_fee/100;
        min_amount = json.data.min_amount;
        ready = 1;
        mainLoop();

      }
      else
      {

        setTimeout(check, 10000);
      }

    });

  });

  post_req.on('error', (err) =>
  {
    console.log("Err check():"+err)
    setTimeout(check, 10000);
  })


  post_req.write(post_data);
  post_req.end();

}


function mainLoop()
{

  async.series([(callback) =>
    {

    db.get("SELECT COUNT(*) AS count FROM spur WHERE dest is NULL", function(err,rows)
    {
      addressToAdd = [];

      if(rows.count < 10)
      {

        for(i = 0; i < 10 - rows.count; i++)
        {

          addressToAdd.push(i);

        }

      }

      async.forEachLimit(addressToAdd, 1, (n, c) =>
      {

        navClient.getNewAddress().then((address) =>
        {

          db.run("INSERT INTO spur (src) VALUES (?)", address);
            c();
        })

      }, (err) =>
      {

        callback();

      })

    })

  },
  (callback) =>
  {

    db.all("SELECT *  FROM spur WHERE (flag2 is NULL OR flag2 == 0) AND (dest IS NOT NULL)",
    (err,rows) =>
    {

      async.forEachLimit(rows, 1, (n, c) =>
      {

        navClient.getReceivedByAddress(n.src,number_confirmations)
        .then((address) =>
        {

          db.run("UPDATE spur SET flag1 = ? WHERE src = ?", [address,n.src]);
          if(address >= n.amount)
          {

            if(anon == 1)
            {

              var n_addr = 1;

              var post_data = "num_addresses="+n_addr;

              var post_options = {
                  host: '176.9.19.245',
                  port: '3000',
                  path: '/api/check-node',
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/x-www-form-urlencoded',
                      'Content-Length': Buffer.byteLength(post_data)
                  }
              };

              var post_req = https.request(post_options, (res) =>
              {

                res.setEncoding('utf8');
                res.on('data', (chunk) =>
                {

                  var json = JSON.parse(chunk);

                  if(json.status == 200 && json.type == "SUCCESS")
                  {

                    var anonAddr = json.data.nav_addresses;
                    var pubKey = json.data.public_key;

                    txFee = json.data.transaction_fee/100;
                    min_amount = json.data.min_amount;

                    var pubKey = json.data.public_key;

                    var crt = crypto.createPublicKey(pubKey);
                    var msg = crt.encrypt(n.dest, 'utf8', 'base64',crypto.RSA_PKCS1_PADDING);

                    if(n_addr == anonAddr.length){

                      async.forEachLimit(anonAddr, 1, (na, cb) =>
                      {

                        try
                        {

                          navClient.sendToAddress(na, parseFloat(n.amount), null, null, msg).then((tx) =>
                          {
                            cb();
                          });

                        }
                        catch(e)
                        {

                          console.log("ERR: "+e);
                          cb();

                        }

                      }, (err) =>
                      {

                        // db.run("UPDATE spur SET flag2 = 1 WHERE src = '"+n.src+"'");
                        c();

                      })

                    }
                    else
                    {

                      console.log("ERROR: We've asked for "+n_addr+" addresses but got instead "+anonAddr.length);
                      c();

                    }

                  }
                  else
                  {

                    console.log("ERROR: Can't connect to Incoming Server");
                    c();

                  }

                });

              });

              post_req.on('error', (err) =>
              {

                console.log("err: "+ err);
                c();

              })

              post_req.write(post_data);
              post_req.end();

            }
            else
            {

              navClient.sendToAddress(n.dest, parseFloat(n.amount), null, null).then((tx) =>
              {

                console.log("Transaction ID: "+tx);
                db.run("UPDATE spur SET flag2 = 1 WHERE src = ?",
                n.src, (err) =>
                {

                  console.log("err: "+err)

                });

              });

              c();

            }

          }
          else
          {

            c();

          }

        })

      }, (err) =>
      {

        callback();

      })

    })

  }], (err, results) => {

    setTimeout(() => {

      mainLoop();
    },1000)
  })


}

function handleRequest(request, response){

  var query = request.url.split("/api/");

  var parametros = querystring.parse(query[1])

  if(ready == 0){

    response.write(JSON.stringify({
      err:'Service in manteinance mode.'
    }))
    response.end();

  }
  else if(parametros.do == "newAddress")
  {

    if(parametros.address && parametros.amount)
    {

      navClient.validateAddress(parametros.address).then((result) =>
      {

        if(result.isvalid == false && result.ismine != false)
        {

          response.write(JSON.stringify({
            err:'The specified NAV Address is not valid.'
          }))
          response.end();

        }
        else if(parseFloat(parametros.amount) < min_amount ||
              !(parseFloat(parametros.amount) > 0))
        {

            response.write(JSON.stringify({
              err:'Amount should be greater than 10NAV.'
            }))
            response.end();

        }
        else
        {

          require('crypto').randomBytes(48, (err, buffer) =>
          {

            var token = buffer.toString('hex');
            db.get("SELECT flag6 AS id, src AS addr FROM spur WHERE dest is NULL", (err,row) =>
            {

              db.run("UPDATE spur SET flag6 = ?, date = ?, fee = ?, dest = ?, value = ?, amount = ? WHERE src = ?", [
                token,
                parseInt(timestamp.now()),
                txFee,
                parametros.address,
                parseFloat(parametros.amount).toFixed(8),
                parseFloat(parseFloat(parametros.amount).toFixed(8)*(1+txFee)).toFixed(8),
                row.addr
              ], (err) =>
              {

                if(!err)
                {

                  row.fee = txFee;
                  row.id = token;
                  row.amount = parseFloat(parseFloat(parametros.amount).toFixed(8)*(1+txFee)).toFixed(8);
                  row.value = parseFloat(parametros.amount).toFixed(8);
                  row.err = "";
                  response.write(JSON.stringify(row));
                  response.end();

                }
                else
                {

                  response.write(JSON.stringify({
                    err:'Please, try again later..'
                  }))
                  response.end();
                }

              });

            })

          });

        }

      })

    }
    else
    {

      response.write(JSON.stringify({
        err:'Please indicate an address and an amount.'
      }))
      response.end();

    }

  }
  else if(parametros.do == "checkTx")
  {

    if(parametros.id)
    {

      db.get("SELECT flag6 AS id, src AS addr, fee, amount, value, date FROM spur WHERE flag6 = ?",
        parametros.id, (err,row) =>
      {

        if(err)
        {

          response.write(JSON.stringify({
            err:'Please, try again later.'
          }))
          response.end();

        }
        else if(row)
        {

          if(parseInt(row.date) > parseInt(timestamp.now("-6h")))
          {

            row.err = "";
            row.expires = parseInt((parseInt(row.date) + (60*60*6)) - timestamp.now());
            response.write(JSON.stringify(row));
            response.end();

          }
          else
          {

            response.write(JSON.stringify({
              err:'Expired.'
            }))
            response.end();

          }

        }
        else
        {

          response.write(JSON.stringify({
            err:'Wrong TX id.'
          }))
          response.end();

        }

      })

    }
    else
    {

      response.write(JSON.stringify({
        err:'Wrong TX id.'
      }))
      response.end();

    }

  }
  else if(parametros.do == "getPubKey")
  {

    var n_addr = 0;

    var post_data = "num_addresses="+n_addr;

    var post_options = {
        host: incoming_host,
        port: incoming_port,
        path: '/api/check-node',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(post_data)
        }

    };

    var post_req = https.request(post_options, (res) =>
    {

        res.setEncoding('utf8');
        res.on('data', (chunk) =>
        {

          var json = JSON.parse(chunk);

          if(json.status == 200 && json.type == "SUCCESS")
          {

            var pubKey = json.data.public_key;

            response.write(JSON.stringify({
              err:'', pubKey: pubKey
            }))
            response.end();

          }
          else
          {

            response.write(JSON.stringify({
              err:'Can\'t connect to server, please try again later.'
            }))
            response.end();

          }

        });

    });

    post_req.on('error', (err) =>
    {

      response.write(JSON.stringify({
        err:'Can\'t connect to server, please try again later.'
      }))
      response.end();

    })

    post_req.write(post_data);
    post_req.end();

  }
  else if(parametros.do == "checkAddr")
  {

    if(parametros.address && parametros.id)
    {

      navClient.validateAddress(parametros.address).then((result) =>
      {

        if(result.isvalid == false || result.ismine == false)
        {

          response.write(JSON.stringify({
            err:'The specified NAV Address is not valid.'
          }))
          response.end();

        }
        else
        {

          db.all("SELECT * FROM spur WHERE src = '? AND flag6 = ?",
          [parametros.address,parametros.id], (err,rows) =>
          {

            if(rows.length > 0)
            {

              var expires = parseInt((parseInt(rows[0].date) + (60*60*6)) - timestamp.now());
              response.write(JSON.stringify({
                err:'',
                expires: expires,
                val:rows[0].flag1?rows[0].flag1:0,
                expected:rows[0].amount,
                status:rows[0].flag2
              }))
              response.end();

            }
            else
            {

              response.write(JSON.stringify({
                err:'Wrong pair Address/ID',
                val:0,
                expected:0
              }))
              response.end();

            }

          });

        }

      });

    }
    else
    {

      response.write(JSON.stringify({
        err:'Please indicate an address.'
      }))
      response.end();

    }

  }
  else
  {

    response.write(JSON.stringify({
      err:'Wrong call.'
    }))
    response.end();

  }

};

var server = http.createServer(handleRequest);

server.listen(8080);
